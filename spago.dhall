{ name = "purescript-webauthn"
, dependencies =
  [ "aff"
  , "arraybuffer-types"
  , "arrays"
  , "effect"
  , "either"
  , "foreign-object"
  , "maybe"
  , "prelude"
  , "tuples"
  , "unsafe-coerce"
  , "web-promise"
  ]
, packages = ./packages.dhall
, sources = [ "src/**/*.purs" ]
}
