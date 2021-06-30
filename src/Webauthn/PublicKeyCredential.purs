-- TODO: Extensions

module Webauthn.PublicKeyCredential
  ( get
  , create
  , isUserVerifyingPlatformAuthenticatorAvailable
  , getTransports
  , PublicKeyCredential
  , PublicKeyCredentialCreationOptions
  , defaultCreationOptions
  , PublicKeyCredentialRequestOptions
  , defaultCredentialRequestOptions
  , Transport(..)
  , UserVerification(..)
  , PublicKeyAlgorithm(..)
  , AuthenticatorAttachment(..)
  , Attestation(..)
  , RelyingParty
  , User
  , CredentialDescriptor
  , AuthenticatorSelection
  , AuthenticatorAttestationResponse
  , AuthenticatorAssertionResponse
  ) where

import Prelude

import Data.Array as Array
import Data.ArrayBuffer.Types (ArrayBuffer)
import Data.Either (Either(..))
import Data.Maybe (Maybe(..), fromMaybe)
import Data.Tuple.Nested ((/\))
import Effect (Effect)
import Effect.Aff (Aff, effectCanceler, error, makeAff)
import Effect.Uncurried (EffectFn1, runEffectFn1)
import Foreign.Object as FO
import Unsafe.Coerce (unsafeCoerce)
import Web.Promise (Promise)
import Web.Promise as Promise
import Web.Promise.Rejection as Rejection

foreign import data Foreign :: Type
encodeInt :: Int -> Foreign
encodeInt = unsafeCoerce

encodeNumber :: Number -> Foreign
encodeNumber = unsafeCoerce

encodeString :: String -> Foreign
encodeString = unsafeCoerce

encodeBoolean :: Boolean -> Foreign
encodeBoolean = unsafeCoerce

encodeObject :: FO.Object Foreign -> Foreign
encodeObject = unsafeCoerce

encodeArray :: Array Foreign -> Foreign
encodeArray = unsafeCoerce

encodeArrayBuffer :: ArrayBuffer -> Foreign
encodeArrayBuffer = unsafeCoerce

type PublicKeyCredential a = {
  id :: String,
  rawId :: ArrayBuffer,
  response :: a
}

data PublicKeyAlgorithm
  = ECDSA_WITH_SHA256
  | RSA_WITH_SHA256
  | OtherAlg Int

encodeAlg :: PublicKeyAlgorithm -> Foreign
encodeAlg = encodeInt <<< case _ of
  ECDSA_WITH_SHA256 -> -7
  RSA_WITH_SHA256 -> -257
  OtherAlg x -> x

type RelyingParty = {
  icon :: Maybe String,
  id :: Maybe String,
  name :: String
}

type User = {
  icon :: Maybe String,
  displayName :: String,
  id :: ArrayBuffer,
  name :: String
}

data Transport
  = USB
  | NFC
  | BLE
  | INTERNAL

encodeTransport :: Transport -> Foreign
encodeTransport = encodeString <<< case _ of
  USB -> "usb"
  NFC -> "nfc"
  BLE -> "ble"
  INTERNAL -> "internal"

readTransport :: String -> Maybe Transport
readTransport = case _ of
  "usb" -> Just USB
  "nfc" -> Just NFC
  "ble" -> Just BLE
  "internal" -> Just INTERNAL
  _ -> Nothing

data Attestation
  = NONE
  | INDIRECT
  | DIRECT

encodeAttestation :: Attestation -> Foreign
encodeAttestation = encodeString <<< case _ of
  NONE -> "none"
  INDIRECT -> "indirect"
  DIRECT -> "direct"

type CredentialDescriptor = {
  id :: ArrayBuffer,
  transports :: Maybe (Array Transport)
}

encodeCredentialDescriptor :: CredentialDescriptor -> Foreign
encodeCredentialDescriptor { id, transports } = encodeObject $
  FO.fromFoldable (Array.catMaybes
    [ Just ("type" /\ encodeString "public-key")
    , Just ("id" /\ encodeArrayBuffer id)
    , map (\ts -> "transports" /\ encodeArray (map encodeTransport ts)) transports
    ])

data AuthenticatorAttachment = PLATFORM | CROSS_PLATFORM

encodeAuthenticatorAttachment :: AuthenticatorAttachment -> Foreign
encodeAuthenticatorAttachment = encodeString <<< case _ of
  PLATFORM -> "platform"
  CROSS_PLATFORM -> "cross-platform"

data UserVerification = REQUIRED | PREFERRED | DISCOURAGED

encodeUserVerification :: UserVerification -> Foreign
encodeUserVerification = encodeString <<< case _ of
  REQUIRED -> "required"
  PREFERRED -> "preferred"
  DISCOURAGED -> "discouraged"

type AuthenticatorSelection = {
  authenticatorAttachmentOptional :: Maybe AuthenticatorAttachment,
  requireResidentKey :: Maybe Boolean,
  userVerification :: Maybe UserVerification
}

encodeAuthenticatorSelection :: AuthenticatorSelection -> Foreign
encodeAuthenticatorSelection as = encodeObject $
  FO.fromFoldable (Array.catMaybes
    [ map (\i -> "authenticatorAttachmentOptional" /\ encodeAuthenticatorAttachment i) as.authenticatorAttachmentOptional
    , map (\i -> "requireResidentKey" /\ encodeBoolean i) as.requireResidentKey
    , map (\i -> "userVerification" /\ encodeUserVerification i) as.userVerification
    ])

type PublicKeyCredentialCreationOptions = {
  rp :: RelyingParty,
  user :: User,
  challenge :: ArrayBuffer,
  pubKeyCredParams :: Array PublicKeyAlgorithm,
  timeout :: Maybe Number,
  excludeCredentials :: Maybe (Array CredentialDescriptor),
  authenticatorSelection :: Maybe AuthenticatorSelection,
  attestation :: Maybe Attestation
}

defaultCreationOptions ::
  { rp :: RelyingParty
  , user :: User
  , challenge :: ArrayBuffer
  , pubKeyCredParams :: Array PublicKeyAlgorithm
  } ->
  PublicKeyCredentialCreationOptions
defaultCreationOptions { rp, user, challenge, pubKeyCredParams } =
  { rp
  , user
  , challenge
  , pubKeyCredParams
  , timeout: Nothing
  , excludeCredentials: Nothing
  , authenticatorSelection: Nothing
  , attestation: Nothing
  }

encodeRelyingParty :: RelyingParty -> Foreign
encodeRelyingParty { icon, id, name } = encodeObject $
  FO.fromFoldable (Array.catMaybes
    [ map (\i -> "id" /\ encodeString i) id
    , Just ("name" /\ encodeString name)
    , map (\i -> "icon" /\ encodeString i) icon
    ])

encodeUser :: User -> Foreign
encodeUser { icon, id, name, displayName } = encodeObject $
  FO.fromFoldable (Array.catMaybes
    [ Just ("id" /\ encodeArrayBuffer id)
    , Just ("name" /\ encodeString name)
    , map (\i -> "icon" /\ encodeString i) icon
    , Just ("displayName" /\ encodeString displayName)
    ])

encodePublicKeyCredentialParam :: PublicKeyAlgorithm -> Foreign
encodePublicKeyCredentialParam alg = encodeObject $
  FO.fromFoldable
    [ "type" /\ encodeString "public-key"
    , "alg" /\ encodeAlg alg
    ]

encodePublicKeyCredentialCreationOptions :: PublicKeyCredentialCreationOptions -> Foreign
encodePublicKeyCredentialCreationOptions opts = encodeObject $
  FO.fromFoldable (Array.catMaybes
    [ Just ("challenge" /\ encodeArrayBuffer opts.challenge)
    , Just ("rp" /\ encodeRelyingParty opts.rp)
    , Just ("user" /\ encodeUser opts.user)
    , Just ("pubKeyCredParams" /\ encodeArray (map encodePublicKeyCredentialParam opts.pubKeyCredParams))
    , map (\to -> "timeout" /\ encodeNumber to) opts.timeout
    , map (\ec -> "excludeCredentials" /\ encodeArray (map encodeCredentialDescriptor ec)) opts.excludeCredentials
    , map (\as -> "authenticatorSelection" /\ encodeAuthenticatorSelection as) opts.authenticatorSelection
    , map (\a -> "attestation" /\ encodeAttestation a) opts.attestation
    ])

type PublicKeyCredentialRequestOptions = {
  challenge :: ArrayBuffer,
  timeout :: Maybe Number,
  rpId :: Maybe String,
  allowCredentials :: Maybe (Array CredentialDescriptor),
  userVerification :: Maybe UserVerification
}

defaultCredentialRequestOptions :: { challenge :: ArrayBuffer } -> PublicKeyCredentialRequestOptions
defaultCredentialRequestOptions { challenge } =
  { challenge
  , timeout: Nothing
  , rpId: Nothing
  , allowCredentials: Nothing
  , userVerification: Nothing
  }

encodePublicKeyCredentialRequestOptions :: PublicKeyCredentialRequestOptions -> Foreign
encodePublicKeyCredentialRequestOptions opts = encodeObject $
  FO.fromFoldable (Array.catMaybes
    [ Just ("challenge" /\ encodeArrayBuffer opts.challenge)
    , map (\to -> "timeout" /\ encodeNumber to) opts.timeout
    , map (\rpId -> "rpId" /\ encodeString rpId) opts.rpId
    , map (\ec -> "allowCredentials" /\ encodeArray (map encodeCredentialDescriptor ec)) opts.allowCredentials
    , map (\uf -> "userVerification" /\ encodeUserVerification uf) opts.userVerification
    ])

type AuthenticatorAttestationResponse = {
  clientDataJSON :: ArrayBuffer,
  attestationObject :: ArrayBuffer
}
foreign import getTransportsImpl :: AuthenticatorAttestationResponse -> Array String

getTransports :: AuthenticatorAttestationResponse -> Array Transport
getTransports = Array.mapMaybe readTransport <<< getTransportsImpl

type AuthenticatorAssertionResponse = {
  clientDataJSON :: ArrayBuffer,
  authenticatorData :: ArrayBuffer,
  signature :: ArrayBuffer,
  userHandle :: ArrayBuffer
}

promiseToAff :: forall a. Effect (Promise a) -> Aff a
promiseToAff mkPromise = makeAff \cb -> do
  promise <- mkPromise
  promise1 <-
    Promise.then_ (\c -> do
      cb (Right c)
      pure (Promise.resolve unit)) promise
  _ <-
    Promise.catch (\rejection -> do
      let err = fromMaybe (error "Unable to convert rejection to error") (Rejection.toError rejection)
      cb (Left err)
      pure (Promise.resolve unit)) promise1
  pure (effectCanceler (pure unit))

foreign import createImpl ::
  EffectFn1
    Foreign
    (Promise (PublicKeyCredential AuthenticatorAttestationResponse))
create :: PublicKeyCredentialCreationOptions -> Aff (PublicKeyCredential AuthenticatorAttestationResponse)
create options = promiseToAff $
  runEffectFn1
    createImpl
    (encodeObject (FO.singleton "publicKey" (encodePublicKeyCredentialCreationOptions options)))

foreign import getImpl ::
  EffectFn1
    Foreign
    (Promise (PublicKeyCredential AuthenticatorAssertionResponse))
get :: PublicKeyCredentialRequestOptions -> Aff (PublicKeyCredential AuthenticatorAssertionResponse)
get options = promiseToAff $
  runEffectFn1
    getImpl
    (encodeObject (FO.singleton "publicKey" (encodePublicKeyCredentialRequestOptions options)))

foreign import isUserVerifyingPlatformAuthenticatorAvailableImpl :: Effect (Promise Boolean)
isUserVerifyingPlatformAuthenticatorAvailable :: Aff Boolean
isUserVerifyingPlatformAuthenticatorAvailable = promiseToAff isUserVerifyingPlatformAuthenticatorAvailableImpl
