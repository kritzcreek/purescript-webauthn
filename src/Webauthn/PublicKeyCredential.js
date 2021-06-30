"use strict";
exports.createImpl = function (options) {
  console.log(options);
  return navigator.credentials.create(options);
};

exports.getImpl = function (options) {
  return navigator.credentials.get(options);
};

exports.getTransportsImpl = function (response) {
  return response.getTransports();
};

exports.isUserVerifyingPlatformAuthenticatorAvailableImpl = function () {
  return PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
};
