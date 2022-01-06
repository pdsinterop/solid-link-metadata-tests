(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
Object.defineProperty(exports, "CordovaIFrameNavigator", {
  enumerable: true,
  get: function () {
    return _oidcClient.CordovaIFrameNavigator;
  }
});
Object.defineProperty(exports, "CordovaPopupNavigator", {
  enumerable: true,
  get: function () {
    return _oidcClient.CordovaPopupNavigator;
  }
});
Object.defineProperty(exports, "InMemoryWebStorage", {
  enumerable: true,
  get: function () {
    return _oidcClient.InMemoryWebStorage;
  }
});
Object.defineProperty(exports, "Log", {
  enumerable: true,
  get: function () {
    return _oidcClient.Log;
  }
});
Object.defineProperty(exports, "OidcClient", {
  enumerable: true,
  get: function () {
    return _oidcClient.OidcClient;
  }
});
Object.defineProperty(exports, "SessionMonitor", {
  enumerable: true,
  get: function () {
    return _oidcClient.SessionMonitor;
  }
});
Object.defineProperty(exports, "User", {
  enumerable: true,
  get: function () {
    return _oidcClient.User;
  }
});
Object.defineProperty(exports, "UserManager", {
  enumerable: true,
  get: function () {
    return _oidcClient.UserManager;
  }
});
Object.defineProperty(exports, "Version", {
  enumerable: true,
  get: function () {
    return _oidcClient.Version;
  }
});
Object.defineProperty(exports, "WebStorageStateStore", {
  enumerable: true,
  get: function () {
    return _oidcClient.WebStorageStateStore;
  }
});
exports.clearOidcPersistentStorage = clearOidcPersistentStorage;
exports.getBearerToken = getBearerToken;
exports.getDpopToken = getDpopToken;
exports.refresh = refresh;
exports.registerClient = registerClient;
exports.removeOidcQueryParam = removeOidcQueryParam;

var _oidcClient = require("@inrupt/oidc-client");

var _solidClientAuthnCore = require("@inrupt/solid-client-authn-core");

var _formUrlencoded = _interopRequireDefault(require("form-urlencoded"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function processErrorResponse(responseBody, options) {
  var _a, _b, _c, _d;

  if (responseBody.error === "invalid_redirect_uri") {
    throw new Error(`Dynamic client registration failed: the provided redirect uri [${(_a = options.redirectUrl) === null || _a === void 0 ? void 0 : _a.toString()}] is invalid - ${(_b = responseBody.error_description) !== null && _b !== void 0 ? _b : ""}`);
  }

  if (responseBody.error === "invalid_client_metadata") {
    throw new Error(`Dynamic client registration failed: the provided client metadata ${JSON.stringify(options)} is invalid - ${(_c = responseBody.error_description) !== null && _c !== void 0 ? _c : ""}`);
  }

  throw new Error(`Dynamic client registration failed: ${responseBody.error} - ${(_d = responseBody.error_description) !== null && _d !== void 0 ? _d : ""}`);
}

function validateRegistrationResponse(responseBody, options) {
  if (responseBody.client_id === undefined) {
    throw new Error(`Dynamic client registration failed: no client_id has been found on ${JSON.stringify(responseBody)}`);
  }

  if (options.redirectUrl && (responseBody.redirect_uris === undefined || responseBody.redirect_uris[0] !== options.redirectUrl.toString())) {
    throw new Error(`Dynamic client registration failed: the returned redirect URIs ${JSON.stringify(responseBody.redirect_uris)} don't match the provided ${JSON.stringify([options.redirectUrl.toString()])}`);
  }
}

async function registerClient(options, issuerConfig) {
  var _a;

  if (!issuerConfig.registrationEndpoint) {
    throw new Error("Dynamic Registration could not be completed because the issuer has no registration endpoint.");
  }

  if (!Array.isArray(issuerConfig.idTokenSigningAlgValuesSupported)) {
    throw new Error("The OIDC issuer discovery profile is missing the 'id_token_signing_alg_values_supported' value, which is mandatory.");
  }

  const signingAlg = (0, _solidClientAuthnCore.determineSigningAlg)(issuerConfig.idTokenSigningAlgValuesSupported, _solidClientAuthnCore.PREFERRED_SIGNING_ALG);
  const config = {
    client_name: options.clientName,
    application_type: "web",
    redirect_uris: [(_a = options.redirectUrl) === null || _a === void 0 ? void 0 : _a.toString()],
    subject_type: "public",
    token_endpoint_auth_method: "client_secret_basic",
    id_token_signed_response_alg: signingAlg,
    grant_types: ["authorization_code", "refresh_token"]
  };
  const headers = {
    "Content-Type": "application/json"
  };

  if (options.registrationAccessToken) {
    headers.Authorization = `Bearer ${options.registrationAccessToken}`;
  }

  const registerResponse = await fetch(issuerConfig.registrationEndpoint.toString(), {
    method: "POST",
    headers,
    body: JSON.stringify(config)
  });

  if (registerResponse.ok) {
    const responseBody = await registerResponse.json();
    validateRegistrationResponse(responseBody, options);
    return {
      clientId: responseBody.client_id,
      clientSecret: responseBody.client_secret,
      idTokenSignedResponseAlg: responseBody.id_token_signed_response_alg,
      clientType: "dynamic"
    };
  }

  if (registerResponse.status === 400) {
    processErrorResponse(await registerResponse.json(), options);
  }

  throw new Error(`Dynamic client registration failed: the server returned ${registerResponse.status} ${registerResponse.statusText} - ${await registerResponse.text()}`);
}

function hasError(value) {
  return value.error !== undefined && typeof value.error === "string";
}

function hasErrorDescription(value) {
  return value.error_description !== undefined && typeof value.error_description === "string";
}

function hasErrorUri(value) {
  return value.error_uri !== undefined && typeof value.error_uri === "string";
}

function hasAccessToken(value) {
  return value.access_token !== undefined && typeof value.access_token === "string";
}

function hasIdToken(value) {
  return value.id_token !== undefined && typeof value.id_token === "string";
}

function hasRefreshToken(value) {
  return value.refresh_token !== undefined && typeof value.refresh_token === "string";
}

function hasTokenType(value) {
  return value.token_type !== undefined && typeof value.token_type === "string";
}

function hasExpiresIn(value) {
  return value.expires_in === undefined || typeof value.expires_in === "number";
}

function validatePreconditions(issuer, data) {
  if (data.grantType && (!issuer.grantTypesSupported || !issuer.grantTypesSupported.includes(data.grantType))) {
    throw new Error(`The issuer [${issuer.issuer}] does not support the [${data.grantType}] grant`);
  }

  if (!issuer.tokenEndpoint) {
    throw new Error(`This issuer [${issuer.issuer}] does not have a token endpoint`);
  }
}

function validateTokenEndpointResponse(tokenResponse, dpop) {
  if (hasError(tokenResponse)) {
    throw new _solidClientAuthnCore.OidcProviderError(`Token endpoint returned error [${tokenResponse.error}]${hasErrorDescription(tokenResponse) ? `: ${tokenResponse.error_description}` : ""}${hasErrorUri(tokenResponse) ? ` (see ${tokenResponse.error_uri})` : ""}`, tokenResponse.error, hasErrorDescription(tokenResponse) ? tokenResponse.error_description : undefined);
  }

  if (!hasAccessToken(tokenResponse)) {
    throw new _solidClientAuthnCore.InvalidResponseError(["access_token"]);
  }

  if (!hasIdToken(tokenResponse)) {
    throw new _solidClientAuthnCore.InvalidResponseError(["id_token"]);
  }

  if (!hasTokenType(tokenResponse)) {
    throw new _solidClientAuthnCore.InvalidResponseError(["token_type"]);
  }

  if (!hasExpiresIn(tokenResponse)) {
    throw new _solidClientAuthnCore.InvalidResponseError(["expires_in"]);
  }

  if (!dpop && tokenResponse.token_type.toLowerCase() !== "bearer") {
    throw new Error(`Invalid token endpoint response: requested a [Bearer] token, but got a 'token_type' value of [${tokenResponse.token_type}].`);
  }

  return tokenResponse;
}

async function getTokens(issuer, client, data, dpop) {
  validatePreconditions(issuer, data);
  const headers = {
    "content-type": "application/x-www-form-urlencoded"
  };
  let dpopKey;

  if (dpop) {
    dpopKey = await (0, _solidClientAuthnCore.generateDpopKeyPair)();
    headers.DPoP = await (0, _solidClientAuthnCore.createDpopHeader)(issuer.tokenEndpoint, "POST", dpopKey);
  }

  if (client.clientSecret) {
    headers.Authorization = `Basic ${btoa(`${client.clientId}:${client.clientSecret}`)}`;
  }

  const tokenRequestInit = {
    method: "POST",
    headers,
    body: (0, _formUrlencoded.default)({
      grant_type: data.grantType,
      redirect_uri: data.redirectUrl,
      code: data.code,
      code_verifier: data.codeVerifier,
      client_id: client.clientId
    })
  };
  const rawTokenResponse = await await fetch(issuer.tokenEndpoint, tokenRequestInit);
  const jsonTokenResponse = await rawTokenResponse.json();
  const tokenResponse = validateTokenEndpointResponse(jsonTokenResponse, dpop);
  const webId = await (0, _solidClientAuthnCore.getWebidFromTokenPayload)(tokenResponse.id_token, issuer.jwksUri, issuer.issuer, client.clientId);
  return {
    accessToken: tokenResponse.access_token,
    idToken: tokenResponse.id_token,
    refreshToken: hasRefreshToken(tokenResponse) ? tokenResponse.refresh_token : undefined,
    webId,
    dpopKey,
    expiresIn: tokenResponse.expires_in
  };
}

async function getBearerToken(redirectUrl) {
  let signinResponse;

  try {
    const client = new _oidcClient.OidcClient({
      response_mode: "query",
      loadUserInfo: false
    });
    signinResponse = await client.processSigninResponse(redirectUrl);

    if (client.settings.metadata === undefined) {
      throw new Error("Cannot retrieve issuer metadata from client information in storage.");
    }

    if (client.settings.metadata.jwks_uri === undefined) {
      throw new Error("Missing some issuer metadata from client information in storage: 'jwks_uri' is undefined");
    }

    if (client.settings.metadata.issuer === undefined) {
      throw new Error("Missing some issuer metadata from client information in storage: 'issuer' is undefined");
    }

    if (client.settings.client_id === undefined) {
      throw new Error("Missing some client information in storage: 'client_id' is undefined");
    }

    const webId = await (0, _solidClientAuthnCore.getWebidFromTokenPayload)(signinResponse.id_token, client.settings.metadata.jwks_uri, client.settings.metadata.issuer, client.settings.client_id);
    return {
      accessToken: signinResponse.access_token,
      idToken: signinResponse.id_token,
      webId,
      refreshToken: signinResponse.refresh_token
    };
  } catch (err) {
    throw new Error(`Problem handling Auth Code Grant (Flow) redirect - URL [${redirectUrl}]: ${err}`);
  }
}

async function getDpopToken(issuer, client, data) {
  return getTokens(issuer, client, data, true);
}

async function refresh(refreshToken, issuer, client, dpopKey) {
  const requestBody = {
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    scope: "openid offline_access"
  };
  let dpopHeader = {};

  if (dpopKey !== undefined) {
    dpopHeader = {
      DPoP: await (0, _solidClientAuthnCore.createDpopHeader)(issuer.tokenEndpoint, "POST", dpopKey)
    };
  }

  let authHeader = {};

  if (client.clientSecret !== undefined) {
    authHeader = {
      Authorization: `Basic ${btoa(`${client.clientId}:${client.clientSecret}`)}`
    };
  }

  const rawResponse = await fetch(issuer.tokenEndpoint, {
    method: "POST",
    body: (0, _formUrlencoded.default)(requestBody),
    headers: { ...dpopHeader,
      ...authHeader,
      "Content-Type": "application/x-www-form-urlencoded"
    }
  });
  let response;

  try {
    response = await rawResponse.json();
  } catch (e) {
    throw new Error(`The token endpoint of issuer ${issuer.issuer} returned a malformed response.`);
  }

  const validatedResponse = validateTokenEndpointResponse(response, dpopKey !== undefined);
  const webId = await (0, _solidClientAuthnCore.getWebidFromTokenPayload)(validatedResponse.id_token, issuer.jwksUri, issuer.issuer, client.clientId);
  return {
    accessToken: validatedResponse.access_token,
    idToken: validatedResponse.id_token,
    refreshToken: typeof validatedResponse.refresh_token === "string" ? validatedResponse.refresh_token : undefined,
    webId,
    dpopKey,
    expiresIn: validatedResponse.expires_in
  };
}

function removeOidcQueryParam(redirectUrl) {
  const cleanedUrl = new URL(redirectUrl);
  cleanedUrl.searchParams.delete("code");
  cleanedUrl.searchParams.delete("state");
  cleanedUrl.hash = "";
  return cleanedUrl.toString();
}

async function clearOidcPersistentStorage() {
  const client = new _oidcClient.OidcClient({
    response_mode: "query"
  });
  await client.clearStaleState(new _oidcClient.WebStorageStateStore({}));
  const myStorage = window.localStorage;
  const itemsToRemove = [];

  for (let i = 0; i <= myStorage.length; i += 1) {
    const key = myStorage.key(i);

    if (key && (key.match(/^oidc\..+$/) || key.match(/^solidClientAuthenticationUser:.+$/))) {
      itemsToRemove.push(key);
    }
  }

  itemsToRemove.forEach(key => myStorage.removeItem(key));
}

},{"@inrupt/oidc-client":2,"@inrupt/solid-client-authn-core":33,"form-urlencoded":47}],2:[function(require,module,exports){
!function t(e,r){if("object"==typeof exports&&"object"==typeof module)module.exports=r();else if("function"==typeof define&&define.amd)define([],r);else{var n=r();for(var i in n)("object"==typeof exports?exports:e)[i]=n[i]}}(this,(function(){return function(t){var e={};function r(n){if(e[n])return e[n].exports;var i=e[n]={i:n,l:!1,exports:{}};return t[n].call(i.exports,i,i.exports,r),i.l=!0,i.exports}return r.m=t,r.c=e,r.d=function(t,e,n){r.o(t,e)||Object.defineProperty(t,e,{enumerable:!0,get:n})},r.r=function(t){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(t,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(t,"__esModule",{value:!0})},r.t=function(t,e){if(1&e&&(t=r(t)),8&e)return t;if(4&e&&"object"==typeof t&&t&&t.__esModule)return t;var n=Object.create(null);if(r.r(n),Object.defineProperty(n,"default",{enumerable:!0,value:t}),2&e&&"string"!=typeof t)for(var i in t)r.d(n,i,function(e){return t[e]}.bind(null,i));return n},r.n=function(t){var e=t&&t.__esModule?function e(){return t.default}:function e(){return t};return r.d(e,"a",e),e},r.o=function(t,e){return Object.prototype.hasOwnProperty.call(t,e)},r.p="",r(r.s=22)}([function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0});var n=function(){function t(t,e){for(var r=0;r<e.length;r++){var n=e[r];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,r,n){return r&&t(e.prototype,r),n&&t(e,n),e}}();var i={debug:function t(){},info:function t(){},warn:function t(){},error:function t(){}},o=void 0,s=void 0;(e.Log=function(){function t(){!function e(t,r){if(!(t instanceof r))throw new TypeError("Cannot call a class as a function")}(this,t)}return t.reset=function t(){s=3,o=i},t.debug=function t(){if(s>=4){for(var e=arguments.length,r=Array(e),n=0;n<e;n++)r[n]=arguments[n];o.debug.apply(o,Array.from(r))}},t.info=function t(){if(s>=3){for(var e=arguments.length,r=Array(e),n=0;n<e;n++)r[n]=arguments[n];o.info.apply(o,Array.from(r))}},t.warn=function t(){if(s>=2){for(var e=arguments.length,r=Array(e),n=0;n<e;n++)r[n]=arguments[n];o.warn.apply(o,Array.from(r))}},t.error=function t(){if(s>=1){for(var e=arguments.length,r=Array(e),n=0;n<e;n++)r[n]=arguments[n];o.error.apply(o,Array.from(r))}},n(t,null,[{key:"NONE",get:function t(){return 0}},{key:"ERROR",get:function t(){return 1}},{key:"WARN",get:function t(){return 2}},{key:"INFO",get:function t(){return 3}},{key:"DEBUG",get:function t(){return 4}},{key:"level",get:function t(){return s},set:function t(e){if(!(0<=e&&e<=4))throw new Error("Invalid log level");s=e}},{key:"logger",get:function t(){return o},set:function t(e){if(!e.debug&&e.info&&(e.debug=e.info),!(e.debug&&e.info&&e.warn&&e.error))throw new Error("Invalid logger");o=e}}]),t}()).reset()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0});var n=function(){function t(t,e){for(var r=0;r<e.length;r++){var n=e[r];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,r,n){return r&&t(e.prototype,r),n&&t(e,n),e}}();var i={setInterval:function(t){function e(e,r){return t.apply(this,arguments)}return e.toString=function(){return t.toString()},e}((function(t,e){return setInterval(t,e)})),clearInterval:function(t){function e(e){return t.apply(this,arguments)}return e.toString=function(){return t.toString()},e}((function(t){return clearInterval(t)}))},o=!1,s=null;e.Global=function(){function t(){!function e(t,r){if(!(t instanceof r))throw new TypeError("Cannot call a class as a function")}(this,t)}return t._testing=function t(){o=!0},t.setXMLHttpRequest=function t(e){s=e},n(t,null,[{key:"location",get:function t(){if(!o)return location}},{key:"localStorage",get:function t(){if(!o&&"undefined"!=typeof window)return localStorage}},{key:"sessionStorage",get:function t(){if(!o&&"undefined"!=typeof window)return sessionStorage}},{key:"XMLHttpRequest",get:function t(){if(!o&&"undefined"!=typeof window)return s||XMLHttpRequest}},{key:"timer",get:function t(){if(!o)return i}}]),t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.MetadataService=void 0;var n=function(){function t(t,e){for(var r=0;r<e.length;r++){var n=e[r];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,r,n){return r&&t(e.prototype,r),n&&t(e,n),e}}(),i=r(0),o=r(7);function s(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}var a=".well-known/openid-configuration";e.MetadataService=function(){function t(e){var r=arguments.length>1&&void 0!==arguments[1]?arguments[1]:o.JsonService;if(s(this,t),!e)throw i.Log.error("MetadataService: No settings passed to MetadataService"),new Error("settings");this._settings=e,this._jsonService=new r(["application/jwk-set+json"])}return t.prototype.resetSigningKeys=function t(){this._settings=this._settings||{},this._settings.signingKeys=void 0},t.prototype.getMetadata=function t(){var e=this;return this._settings.metadata?(i.Log.debug("MetadataService.getMetadata: Returning metadata from settings"),Promise.resolve(this._settings.metadata)):this.metadataUrl?(i.Log.debug("MetadataService.getMetadata: getting metadata from",this.metadataUrl),this._jsonService.getJson(this.metadataUrl).then((function(t){i.Log.debug("MetadataService.getMetadata: json received");var r=e._settings.metadataSeed||{};return e._settings.metadata=Object.assign({},r,t),e._settings.metadata}))):(i.Log.error("MetadataService.getMetadata: No authority or metadataUrl configured on settings"),Promise.reject(new Error("No authority or metadataUrl configured on settings")))},t.prototype.getIssuer=function t(){return this._getMetadataProperty("issuer")},t.prototype.getAuthorizationEndpoint=function t(){return this._getMetadataProperty("authorization_endpoint")},t.prototype.getUserInfoEndpoint=function t(){return this._getMetadataProperty("userinfo_endpoint")},t.prototype.getTokenEndpoint=function t(){var e=!(arguments.length>0&&void 0!==arguments[0])||arguments[0];return this._getMetadataProperty("token_endpoint",e)},t.prototype.getCheckSessionIframe=function t(){return this._getMetadataProperty("check_session_iframe",!0)},t.prototype.getEndSessionEndpoint=function t(){return this._getMetadataProperty("end_session_endpoint",!0)},t.prototype.getRevocationEndpoint=function t(){return this._getMetadataProperty("revocation_endpoint",!0)},t.prototype.getKeysEndpoint=function t(){return this._getMetadataProperty("jwks_uri",!0)},t.prototype._getMetadataProperty=function t(e){var r=arguments.length>1&&void 0!==arguments[1]&&arguments[1];return i.Log.debug("MetadataService.getMetadataProperty for: "+e),this.getMetadata().then((function(t){if(i.Log.debug("MetadataService.getMetadataProperty: metadata recieved"),void 0===t[e]){if(!0===r)return void i.Log.warn("MetadataService.getMetadataProperty: Metadata does not contain optional property "+e);throw i.Log.error("MetadataService.getMetadataProperty: Metadata does not contain property "+e),new Error("Metadata does not contain property "+e)}return t[e]}))},t.prototype.getSigningKeys=function t(){var e=this;return this._settings.signingKeys?(i.Log.debug("MetadataService.getSigningKeys: Returning signingKeys from settings"),Promise.resolve(this._settings.signingKeys)):this._getMetadataProperty("jwks_uri").then((function(t){return i.Log.debug("MetadataService.getSigningKeys: jwks_uri received",t),e._jsonService.getJson(t).then((function(t){if(i.Log.debug("MetadataService.getSigningKeys: key set received",t),!t.keys)throw i.Log.error("MetadataService.getSigningKeys: Missing keys on keyset"),new Error("Missing keys on keyset");return e._settings.signingKeys=t.keys,e._settings.signingKeys}))}))},n(t,[{key:"metadataUrl",get:function t(){return this._metadataUrl||(this._settings.metadataUrl?this._metadataUrl=this._settings.metadataUrl:(this._metadataUrl=this._settings.authority,this._metadataUrl&&this._metadataUrl.indexOf(a)<0&&("/"!==this._metadataUrl[this._metadataUrl.length-1]&&(this._metadataUrl+="/"),this._metadataUrl+=a))),this._metadataUrl}}]),t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.UrlUtility=void 0;var n=r(0),i=r(1);e.UrlUtility=function(){function t(){!function e(t,r){if(!(t instanceof r))throw new TypeError("Cannot call a class as a function")}(this,t)}return t.addQueryParam=function t(e,r,n){return e.indexOf("?")<0&&(e+="?"),"?"!==e[e.length-1]&&(e+="&"),e+=encodeURIComponent(r),e+="=",e+=encodeURIComponent(n)},t.parseUrlFragment=function t(e){var r=arguments.length>1&&void 0!==arguments[1]?arguments[1]:"#",o=arguments.length>2&&void 0!==arguments[2]?arguments[2]:i.Global;"string"!=typeof e&&(e=o.location.href);var s=e.lastIndexOf(r);s>=0&&(e=e.substr(s+1)),"?"===r&&(s=e.indexOf("#"))>=0&&(e=e.substr(0,s));for(var a,u={},c=/([^&=]+)=([^&]*)/g,h=0;a=c.exec(e);)if(u[decodeURIComponent(a[1])]=decodeURIComponent(a[2].replace(/\+/g," ")),h++>50)return n.Log.error("UrlUtility.parseUrlFragment: response exceeded expected number of parameters",e),{error:"Response exceeded expected number of parameters"};for(var l in u)return u;return{}},t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.JoseUtil=void 0;var n=r(26),i=function o(t){return t&&t.__esModule?t:{default:t}}(r(33));e.JoseUtil=(0,i.default)({jws:n.jws,KeyUtil:n.KeyUtil,X509:n.X509,crypto:n.crypto,hextob64u:n.hextob64u,b64tohex:n.b64tohex,AllowedSigningAlgs:n.AllowedSigningAlgs})},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.OidcClientSettings=void 0;var n="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(t){return typeof t}:function(t){return t&&"function"==typeof Symbol&&t.constructor===Symbol&&t!==Symbol.prototype?"symbol":typeof t},i=function(){function t(t,e){for(var r=0;r<e.length;r++){var n=e[r];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,r,n){return r&&t(e.prototype,r),n&&t(e,n),e}}(),o=r(0),s=r(23),a=r(6),u=r(24),c=r(2);function h(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}var l=".well-known/openid-configuration",f="id_token",g="openid",d="client_secret_post";e.OidcClientSettings=function(){function t(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},r=e.authority,i=e.metadataUrl,o=e.metadata,l=e.signingKeys,p=e.metadataSeed,v=e.client_id,y=e.client_secret,m=e.response_type,_=void 0===m?f:m,S=e.scope,b=void 0===S?g:S,w=e.redirect_uri,F=e.post_logout_redirect_uri,E=e.client_authentication,x=void 0===E?d:E,A=e.prompt,k=e.display,P=e.max_age,C=e.ui_locales,T=e.acr_values,R=e.resource,I=e.response_mode,D=e.filterProtocolClaims,L=void 0===D||D,N=e.loadUserInfo,U=void 0===N||N,B=e.staleStateAge,O=void 0===B?900:B,j=e.clockSkew,M=void 0===j?300:j,H=e.clockService,V=void 0===H?new s.ClockService:H,K=e.userInfoJwtIssuer,q=void 0===K?"OP":K,J=e.mergeClaims,W=void 0!==J&&J,z=e.stateStore,Y=void 0===z?new a.WebStorageStateStore:z,G=e.ResponseValidatorCtor,X=void 0===G?u.ResponseValidator:G,$=e.MetadataServiceCtor,Q=void 0===$?c.MetadataService:$,Z=e.extraQueryParams,tt=void 0===Z?{}:Z,et=e.extraTokenParams,rt=void 0===et?{}:et;h(this,t),this._authority=r,this._metadataUrl=i,this._metadata=o,this._metadataSeed=p,this._signingKeys=l,this._client_id=v,this._client_secret=y,this._response_type=_,this._scope=b,this._redirect_uri=w,this._post_logout_redirect_uri=F,this._client_authentication=x,this._prompt=A,this._display=k,this._max_age=P,this._ui_locales=C,this._acr_values=T,this._resource=R,this._response_mode=I,this._filterProtocolClaims=!!L,this._loadUserInfo=!!U,this._staleStateAge=O,this._clockSkew=M,this._clockService=V,this._userInfoJwtIssuer=q,this._mergeClaims=!!W,this._stateStore=Y,this._validator=new X(this),this._metadataService=new Q(this),this._extraQueryParams="object"===(void 0===tt?"undefined":n(tt))?tt:{},this._extraTokenParams="object"===(void 0===rt?"undefined":n(rt))?rt:{}}return t.prototype.getEpochTime=function t(){return this._clockService.getEpochTime()},i(t,[{key:"client_id",get:function t(){return this._client_id},set:function t(e){if(this._client_id)throw o.Log.error("OidcClientSettings.set_client_id: client_id has already been assigned."),new Error("client_id has already been assigned.");this._client_id=e}},{key:"client_secret",get:function t(){return this._client_secret}},{key:"response_type",get:function t(){return this._response_type}},{key:"scope",get:function t(){return this._scope}},{key:"redirect_uri",get:function t(){return this._redirect_uri}},{key:"post_logout_redirect_uri",get:function t(){return this._post_logout_redirect_uri}},{key:"client_authentication",get:function t(){return this._client_authentication}},{key:"prompt",get:function t(){return this._prompt}},{key:"display",get:function t(){return this._display}},{key:"max_age",get:function t(){return this._max_age}},{key:"ui_locales",get:function t(){return this._ui_locales}},{key:"acr_values",get:function t(){return this._acr_values}},{key:"resource",get:function t(){return this._resource}},{key:"response_mode",get:function t(){return this._response_mode}},{key:"authority",get:function t(){return this._authority},set:function t(e){if(this._authority)throw o.Log.error("OidcClientSettings.set_authority: authority has already been assigned."),new Error("authority has already been assigned.");this._authority=e}},{key:"metadataUrl",get:function t(){return this._metadataUrl||(this._metadataUrl=this.authority,this._metadataUrl&&this._metadataUrl.indexOf(l)<0&&("/"!==this._metadataUrl[this._metadataUrl.length-1]&&(this._metadataUrl+="/"),this._metadataUrl+=l)),this._metadataUrl}},{key:"metadata",get:function t(){return this._metadata},set:function t(e){this._metadata=e}},{key:"metadataSeed",get:function t(){return this._metadataSeed},set:function t(e){this._metadataSeed=e}},{key:"signingKeys",get:function t(){return this._signingKeys},set:function t(e){this._signingKeys=e}},{key:"filterProtocolClaims",get:function t(){return this._filterProtocolClaims}},{key:"loadUserInfo",get:function t(){return this._loadUserInfo}},{key:"staleStateAge",get:function t(){return this._staleStateAge}},{key:"clockSkew",get:function t(){return this._clockSkew}},{key:"userInfoJwtIssuer",get:function t(){return this._userInfoJwtIssuer}},{key:"mergeClaims",get:function t(){return this._mergeClaims}},{key:"stateStore",get:function t(){return this._stateStore}},{key:"validator",get:function t(){return this._validator}},{key:"metadataService",get:function t(){return this._metadataService}},{key:"extraQueryParams",get:function t(){return this._extraQueryParams},set:function t(e){"object"===(void 0===e?"undefined":n(e))?this._extraQueryParams=e:this._extraQueryParams={}}},{key:"extraTokenParams",get:function t(){return this._extraTokenParams},set:function t(e){"object"===(void 0===e?"undefined":n(e))?this._extraTokenParams=e:this._extraTokenParams={}}}]),t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.WebStorageStateStore=void 0;var n=r(0),i=r(1);function o(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}e.WebStorageStateStore=function(){function t(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},r=e.prefix,n=void 0===r?"oidc.":r,s=e.store,a=void 0===s?i.Global.localStorage:s;o(this,t),this._store=a,this._prefix=n}return t.prototype.set=function t(e,r){return n.Log.debug("WebStorageStateStore.set",e),e=this._prefix+e,this._store.setItem(e,r),Promise.resolve()},t.prototype.get=function t(e){n.Log.debug("WebStorageStateStore.get",e),e=this._prefix+e;var r=this._store.getItem(e);return Promise.resolve(r)},t.prototype.remove=function t(e){n.Log.debug("WebStorageStateStore.remove",e),e=this._prefix+e;var r=this._store.getItem(e);return this._store.removeItem(e),Promise.resolve(r)},t.prototype.getAllKeys=function t(){n.Log.debug("WebStorageStateStore.getAllKeys");for(var e=[],r=0;r<this._store.length;r++){var i=this._store.key(r);0===i.indexOf(this._prefix)&&e.push(i.substr(this._prefix.length))}return Promise.resolve(e)},t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.JsonService=void 0;var n=r(0),i=r(1);function o(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}e.JsonService=function(){function t(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:null,r=arguments.length>1&&void 0!==arguments[1]?arguments[1]:i.Global.XMLHttpRequest,n=arguments.length>2&&void 0!==arguments[2]?arguments[2]:null;o(this,t),e&&Array.isArray(e)?this._contentTypes=e.slice():this._contentTypes=[],this._contentTypes.push("application/json"),n&&this._contentTypes.push("application/jwt"),this._XMLHttpRequest=r,this._jwtHandler=n}return t.prototype.getJson=function t(e,r){var i=this;if(!e)throw n.Log.error("JsonService.getJson: No url passed"),new Error("url");return n.Log.debug("JsonService.getJson, url: ",e),new Promise((function(t,o){var s=new i._XMLHttpRequest;s.open("GET",e);var a=i._contentTypes,u=i._jwtHandler;s.onload=function(){if(n.Log.debug("JsonService.getJson: HTTP response received, status",s.status),200===s.status){var r=s.getResponseHeader("Content-Type");if(r){var i=a.find((function(t){if(r.startsWith(t))return!0}));if("application/jwt"==i)return void u(s).then(t,o);if(i)try{return void t(JSON.parse(s.responseText))}catch(t){return n.Log.error("JsonService.getJson: Error parsing JSON response",t.message),void o(t)}}o(Error("Invalid response Content-Type: "+r+", from URL: "+e))}else o(Error(s.statusText+" ("+s.status+")"))},s.onerror=function(){n.Log.error("JsonService.getJson: network error"),o(Error("Network Error"))},r&&(n.Log.debug("JsonService.getJson: token passed, setting Authorization header"),s.setRequestHeader("Authorization","Bearer "+r)),s.send()}))},t.prototype.postForm=function t(e,r,i){var o=this;if(!e)throw n.Log.error("JsonService.postForm: No url passed"),new Error("url");return n.Log.debug("JsonService.postForm, url: ",e),new Promise((function(t,s){var a=new o._XMLHttpRequest;a.open("POST",e);var u=o._contentTypes;a.onload=function(){if(n.Log.debug("JsonService.postForm: HTTP response received, status",a.status),200!==a.status){if(400===a.status)if(i=a.getResponseHeader("Content-Type"))if(u.find((function(t){if(i.startsWith(t))return!0})))try{var r=JSON.parse(a.responseText);if(r&&r.error)return n.Log.error("JsonService.postForm: Error from server: ",r.error),void s(new Error(r.error))}catch(t){return n.Log.error("JsonService.postForm: Error parsing JSON response",t.message),void s(t)}s(Error(a.statusText+" ("+a.status+")"))}else{var i;if((i=a.getResponseHeader("Content-Type"))&&u.find((function(t){if(i.startsWith(t))return!0})))try{return void t(JSON.parse(a.responseText))}catch(t){return n.Log.error("JsonService.postForm: Error parsing JSON response",t.message),void s(t)}s(Error("Invalid response Content-Type: "+i+", from URL: "+e))}},a.onerror=function(){n.Log.error("JsonService.postForm: network error"),s(Error("Network Error"))};var c="";for(var h in r){var l=r[h];l&&(c.length>0&&(c+="&"),c+=encodeURIComponent(h),c+="=",c+=encodeURIComponent(l))}a.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),void 0!==i&&a.setRequestHeader("Authorization","Basic "+btoa(i)),a.send(c)}))},t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.SigninRequest=void 0;var n=r(0),i=r(3),o=r(13);e.SigninRequest=function(){function t(e){var r=e.url,s=e.client_id,a=e.redirect_uri,u=e.response_type,c=e.scope,h=e.authority,l=e.data,f=e.prompt,g=e.display,d=e.max_age,p=e.ui_locales,v=e.id_token_hint,y=e.login_hint,m=e.acr_values,_=e.resource,S=e.response_mode,b=e.request,w=e.request_uri,F=e.extraQueryParams,E=e.request_type,x=e.client_secret,A=e.extraTokenParams,k=e.skipUserInfo;if(function P(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}(this,t),!r)throw n.Log.error("SigninRequest.ctor: No url passed"),new Error("url");if(!s)throw n.Log.error("SigninRequest.ctor: No client_id passed"),new Error("client_id");if(!a)throw n.Log.error("SigninRequest.ctor: No redirect_uri passed"),new Error("redirect_uri");if(!u)throw n.Log.error("SigninRequest.ctor: No response_type passed"),new Error("response_type");if(!c)throw n.Log.error("SigninRequest.ctor: No scope passed"),new Error("scope");if(!h)throw n.Log.error("SigninRequest.ctor: No authority passed"),new Error("authority");var C=t.isOidc(u),T=t.isCode(u);S||(S=t.isCode(u)?"query":null),this.state=new o.SigninState({nonce:C,data:l,client_id:s,authority:h,redirect_uri:a,code_verifier:T,request_type:E,response_mode:S,client_secret:x,scope:c,extraTokenParams:A,skipUserInfo:k}),r=i.UrlUtility.addQueryParam(r,"client_id",s),r=i.UrlUtility.addQueryParam(r,"redirect_uri",a),r=i.UrlUtility.addQueryParam(r,"response_type",u),r=i.UrlUtility.addQueryParam(r,"scope",c),r=i.UrlUtility.addQueryParam(r,"state",this.state.id),C&&(r=i.UrlUtility.addQueryParam(r,"nonce",this.state.nonce)),T&&(r=i.UrlUtility.addQueryParam(r,"code_challenge",this.state.code_challenge),r=i.UrlUtility.addQueryParam(r,"code_challenge_method","S256"));var R={prompt:f,display:g,max_age:d,ui_locales:p,id_token_hint:v,login_hint:y,acr_values:m,resource:_,request:b,request_uri:w,response_mode:S};for(var I in R)R[I]&&(r=i.UrlUtility.addQueryParam(r,I,R[I]));for(var D in F)r=i.UrlUtility.addQueryParam(r,D,F[D]);this.url=r}return t.isOidc=function t(e){return!!e.split(/\s+/g).filter((function(t){return"id_token"===t}))[0]},t.isOAuth=function t(e){return!!e.split(/\s+/g).filter((function(t){return"token"===t}))[0]},t.isCode=function t(e){return!!e.split(/\s+/g).filter((function(t){return"code"===t}))[0]},t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.State=void 0;var n=function(){function t(t,e){for(var r=0;r<e.length;r++){var n=e[r];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,r,n){return r&&t(e.prototype,r),n&&t(e,n),e}}(),i=r(0),o=function s(t){return t&&t.__esModule?t:{default:t}}(r(14));function a(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}e.State=function(){function t(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},r=e.id,n=e.data,i=e.created,s=e.request_type;a(this,t),this._id=r||(0,o.default)(),this._data=n,this._created="number"==typeof i&&i>0?i:parseInt(Date.now()/1e3),this._request_type=s}return t.prototype.toStorageString=function t(){return i.Log.debug("State.toStorageString"),JSON.stringify({id:this.id,data:this.data,created:this.created,request_type:this.request_type})},t.fromStorageString=function e(r){return i.Log.debug("State.fromStorageString"),new t(JSON.parse(r))},t.clearStaleState=function e(r,n){var o=Date.now()/1e3-n;return r.getAllKeys().then((function(e){i.Log.debug("State.clearStaleState: got keys",e);for(var n=[],s=function s(a){var c=e[a];u=r.get(c).then((function(e){var n=!1;if(e)try{var s=t.fromStorageString(e);i.Log.debug("State.clearStaleState: got item from key: ",c,s.created),s.created<=o&&(n=!0)}catch(t){i.Log.error("State.clearStaleState: Error parsing state for key",c,t.message),n=!0}else i.Log.debug("State.clearStaleState: no item in storage for key: ",c),n=!0;if(n)return i.Log.debug("State.clearStaleState: removed item for key: ",c),r.remove(c)})),n.push(u)},a=0;a<e.length;a++){var u;s(a)}return i.Log.debug("State.clearStaleState: waiting on promise count:",n.length),Promise.all(n)}))},n(t,[{key:"id",get:function t(){return this._id}},{key:"data",get:function t(){return this._data}},{key:"created",get:function t(){return this._created}},{key:"request_type",get:function t(){return this._request_type}}]),t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.OidcClient=void 0;var n=function(){function t(t,e){for(var r=0;r<e.length;r++){var n=e[r];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,r,n){return r&&t(e.prototype,r),n&&t(e,n),e}}(),i=r(0),o=r(5),s=r(12),a=r(8),u=r(34),c=r(35),h=r(36),l=r(13),f=r(9);function g(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}e.OidcClient=function(){function t(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{};g(this,t),e instanceof o.OidcClientSettings?this._settings=e:this._settings=new o.OidcClientSettings(e)}return t.prototype.createSigninRequest=function t(){var e=this,r=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},n=r.response_type,o=r.scope,s=r.redirect_uri,u=r.data,c=r.state,h=r.prompt,l=r.display,f=r.max_age,g=r.ui_locales,d=r.id_token_hint,p=r.login_hint,v=r.acr_values,y=r.resource,m=r.request,_=r.request_uri,S=r.response_mode,b=r.extraQueryParams,w=r.extraTokenParams,F=r.request_type,E=r.skipUserInfo,x=arguments[1];i.Log.debug("OidcClient.createSigninRequest");var A=this._settings.client_id;n=n||this._settings.response_type,o=o||this._settings.scope,s=s||this._settings.redirect_uri,h=h||this._settings.prompt,l=l||this._settings.display,f=f||this._settings.max_age,g=g||this._settings.ui_locales,v=v||this._settings.acr_values,y=y||this._settings.resource,S=S||this._settings.response_mode,b=b||this._settings.extraQueryParams,w=w||this._settings.extraTokenParams;var k=this._settings.authority;return a.SigninRequest.isCode(n)&&"code"!==n?Promise.reject(new Error("OpenID Connect hybrid flow is not supported")):this._metadataService.getAuthorizationEndpoint().then((function(t){i.Log.debug("OidcClient.createSigninRequest: Received authorization endpoint",t);var r=new a.SigninRequest({url:t,client_id:A,redirect_uri:s,response_type:n,scope:o,data:u||c,authority:k,prompt:h,display:l,max_age:f,ui_locales:g,id_token_hint:d,login_hint:p,acr_values:v,resource:y,request:m,request_uri:_,extraQueryParams:b,extraTokenParams:w,request_type:F,response_mode:S,client_secret:e._settings.client_secret,skipUserInfo:E}),P=r.state;return(x=x||e._stateStore).set(P.id,P.toStorageString()).then((function(){return r}))}))},t.prototype.readSigninResponseState=function t(e,r){var n=arguments.length>2&&void 0!==arguments[2]&&arguments[2];i.Log.debug("OidcClient.readSigninResponseState");var o="query"===this._settings.response_mode||!this._settings.response_mode&&a.SigninRequest.isCode(this._settings.response_type),s=o?"?":"#",c=new u.SigninResponse(e,s);if(!c.state)return i.Log.error("OidcClient.readSigninResponseState: No state in response"),Promise.reject(new Error("No state in response"));r=r||this._stateStore;var h=n?r.remove.bind(r):r.get.bind(r);return h(c.state).then((function(t){if(!t)throw i.Log.error("OidcClient.readSigninResponseState: No matching state found in storage"),new Error("No matching state found in storage");return{state:l.SigninState.fromStorageString(t),response:c}}))},t.prototype.processSigninResponse=function t(e,r){var n=this;return i.Log.debug("OidcClient.processSigninResponse"),this.readSigninResponseState(e,r,!0).then((function(t){var e=t.state,r=t.response;return i.Log.debug("OidcClient.processSigninResponse: Received state from storage; validating response"),n._validator.validateSigninResponse(e,r)}))},t.prototype.createSignoutRequest=function t(){var e=this,r=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},n=r.id_token_hint,o=r.data,s=r.state,a=r.post_logout_redirect_uri,u=r.extraQueryParams,h=r.request_type,l=arguments[1];return i.Log.debug("OidcClient.createSignoutRequest"),a=a||this._settings.post_logout_redirect_uri,u=u||this._settings.extraQueryParams,this._metadataService.getEndSessionEndpoint().then((function(t){if(!t)throw i.Log.error("OidcClient.createSignoutRequest: No end session endpoint url returned"),new Error("no end session endpoint");i.Log.debug("OidcClient.createSignoutRequest: Received end session endpoint",t);var r=new c.SignoutRequest({url:t,id_token_hint:n,post_logout_redirect_uri:a,data:o||s,extraQueryParams:u,request_type:h}),f=r.state;return f&&(i.Log.debug("OidcClient.createSignoutRequest: Signout request has state to persist"),(l=l||e._stateStore).set(f.id,f.toStorageString())),r}))},t.prototype.readSignoutResponseState=function t(e,r){var n=arguments.length>2&&void 0!==arguments[2]&&arguments[2];i.Log.debug("OidcClient.readSignoutResponseState");var o=new h.SignoutResponse(e);if(!o.state)return i.Log.debug("OidcClient.readSignoutResponseState: No state in response"),o.error?(i.Log.warn("OidcClient.readSignoutResponseState: Response was error: ",o.error),Promise.reject(new s.ErrorResponse(o))):Promise.resolve({state:void 0,response:o});var a=o.state;r=r||this._stateStore;var u=n?r.remove.bind(r):r.get.bind(r);return u(a).then((function(t){if(!t)throw i.Log.error("OidcClient.readSignoutResponseState: No matching state found in storage"),new Error("No matching state found in storage");return{state:f.State.fromStorageString(t),response:o}}))},t.prototype.processSignoutResponse=function t(e,r){var n=this;return i.Log.debug("OidcClient.processSignoutResponse"),this.readSignoutResponseState(e,r,!0).then((function(t){var e=t.state,r=t.response;return e?(i.Log.debug("OidcClient.processSignoutResponse: Received state from storage; validating response"),n._validator.validateSignoutResponse(e,r)):(i.Log.debug("OidcClient.processSignoutResponse: No state from storage; skipping validating response"),r)}))},t.prototype.clearStaleState=function t(e){return i.Log.debug("OidcClient.clearStaleState"),e=e||this._stateStore,f.State.clearStaleState(e,this.settings.staleStateAge)},n(t,[{key:"_stateStore",get:function t(){return this.settings.stateStore}},{key:"_validator",get:function t(){return this.settings.validator}},{key:"_metadataService",get:function t(){return this.settings.metadataService}},{key:"settings",get:function t(){return this._settings}},{key:"metadataService",get:function t(){return this._metadataService}}]),t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.TokenClient=void 0;var n=r(7),i=r(2),o=r(0);function s(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}e.TokenClient=function(){function t(e){var r=arguments.length>1&&void 0!==arguments[1]?arguments[1]:n.JsonService,a=arguments.length>2&&void 0!==arguments[2]?arguments[2]:i.MetadataService;if(s(this,t),!e)throw o.Log.error("TokenClient.ctor: No settings passed"),new Error("settings");this._settings=e,this._jsonService=new r,this._metadataService=new a(this._settings)}return t.prototype.exchangeCode=function t(){var e=this,r=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{};(r=Object.assign({},r)).grant_type=r.grant_type||"authorization_code",r.client_id=r.client_id||this._settings.client_id,r.client_secret=r.client_secret||this._settings.client_secret,r.redirect_uri=r.redirect_uri||this._settings.redirect_uri;var n=void 0,i=r._client_authentication||this._settings._client_authentication;return delete r._client_authentication,r.code?r.redirect_uri?r.code_verifier?r.client_id?r.client_secret||"client_secret_basic"!=i?("client_secret_basic"==i&&(n=r.client_id+":"+r.client_secret,delete r.client_id,delete r.client_secret),this._metadataService.getTokenEndpoint(!1).then((function(t){return o.Log.debug("TokenClient.exchangeCode: Received token endpoint"),e._jsonService.postForm(t,r,n).then((function(t){return o.Log.debug("TokenClient.exchangeCode: response received"),t}))}))):(o.Log.error("TokenClient.exchangeCode: No client_secret passed"),Promise.reject(new Error("A client_secret is required"))):(o.Log.error("TokenClient.exchangeCode: No client_id passed"),Promise.reject(new Error("A client_id is required"))):(o.Log.error("TokenClient.exchangeCode: No code_verifier passed"),Promise.reject(new Error("A code_verifier is required"))):(o.Log.error("TokenClient.exchangeCode: No redirect_uri passed"),Promise.reject(new Error("A redirect_uri is required"))):(o.Log.error("TokenClient.exchangeCode: No code passed"),Promise.reject(new Error("A code is required")))},t.prototype.exchangeRefreshToken=function t(){var e=this,r=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{};(r=Object.assign({},r)).grant_type=r.grant_type||"refresh_token",r.client_id=r.client_id||this._settings.client_id,r.client_secret=r.client_secret||this._settings.client_secret;var n=void 0,i=r._client_authentication||this._settings._client_authentication;return delete r._client_authentication,r.refresh_token?r.client_id?("client_secret_basic"==i&&(n=r.client_id+":"+r.client_secret,delete r.client_id,delete r.client_secret),this._metadataService.getTokenEndpoint(!1).then((function(t){return o.Log.debug("TokenClient.exchangeRefreshToken: Received token endpoint"),e._jsonService.postForm(t,r,n).then((function(t){return o.Log.debug("TokenClient.exchangeRefreshToken: response received"),t}))}))):(o.Log.error("TokenClient.exchangeRefreshToken: No client_id passed"),Promise.reject(new Error("A client_id is required"))):(o.Log.error("TokenClient.exchangeRefreshToken: No refresh_token passed"),Promise.reject(new Error("A refresh_token is required")))},t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.ErrorResponse=void 0;var n=r(0);function i(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function o(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}e.ErrorResponse=function(t){function e(){var r=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},s=r.error,a=r.error_description,u=r.error_uri,c=r.state,h=r.session_state;if(i(this,e),!s)throw n.Log.error("No error passed to ErrorResponse"),new Error("error");var l=o(this,t.call(this,a||s));return l.name="ErrorResponse",l.error=s,l.error_description=a,l.error_uri=u,l.state=c,l.session_state=h,l}return function r(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}(e,t),e}(Error)},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.SigninState=void 0;var n=function(){function t(t,e){for(var r=0;r<e.length;r++){var n=e[r];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,r,n){return r&&t(e.prototype,r),n&&t(e,n),e}}(),i=r(0),o=r(9),s=r(4),a=function u(t){return t&&t.__esModule?t:{default:t}}(r(14));function c(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function h(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}e.SigninState=function(t){function e(){var r=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},n=r.nonce,i=r.authority,o=r.client_id,u=r.redirect_uri,l=r.code_verifier,f=r.response_mode,g=r.client_secret,d=r.scope,p=r.extraTokenParams,v=r.skipUserInfo;c(this,e);var y=h(this,t.call(this,arguments[0]));if(!0===n?y._nonce=(0,a.default)():n&&(y._nonce=n),!0===l?y._code_verifier=(0,a.default)()+(0,a.default)()+(0,a.default)():l&&(y._code_verifier=l),y.code_verifier){var m=s.JoseUtil.hashString(y.code_verifier,"SHA256");y._code_challenge=s.JoseUtil.hexToBase64Url(m)}return y._redirect_uri=u,y._authority=i,y._client_id=o,y._response_mode=f,y._client_secret=g,y._scope=d,y._extraTokenParams=p,y._skipUserInfo=v,y}return function r(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}(e,t),e.prototype.toStorageString=function t(){return i.Log.debug("SigninState.toStorageString"),JSON.stringify({id:this.id,data:this.data,created:this.created,request_type:this.request_type,nonce:this.nonce,code_verifier:this.code_verifier,redirect_uri:this.redirect_uri,authority:this.authority,client_id:this.client_id,response_mode:this.response_mode,client_secret:this.client_secret,scope:this.scope,extraTokenParams:this.extraTokenParams,skipUserInfo:this.skipUserInfo})},e.fromStorageString=function t(r){return i.Log.debug("SigninState.fromStorageString"),new e(JSON.parse(r))},n(e,[{key:"nonce",get:function t(){return this._nonce}},{key:"authority",get:function t(){return this._authority}},{key:"client_id",get:function t(){return this._client_id}},{key:"redirect_uri",get:function t(){return this._redirect_uri}},{key:"code_verifier",get:function t(){return this._code_verifier}},{key:"code_challenge",get:function t(){return this._code_challenge}},{key:"response_mode",get:function t(){return this._response_mode}},{key:"client_secret",get:function t(){return this._client_secret}},{key:"scope",get:function t(){return this._scope}},{key:"extraTokenParams",get:function t(){return this._extraTokenParams}},{key:"skipUserInfo",get:function t(){return this._skipUserInfo}}]),e}(o.State)},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.default=function n(){return("undefined"!=i&&null!==i&&void 0!==i.getRandomValues?o:s)().replace(/-/g,"")};var i="undefined"!=typeof window?window.crypto||window.msCrypto:null;function o(){return([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g,(function(t){return(t^i.getRandomValues(new Uint8Array(1))[0]&15>>t/4).toString(16)}))}function s(){return([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g,(function(t){return(t^16*Math.random()>>t/4).toString(16)}))}t.exports=e.default},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.User=void 0;var n=function(){function t(t,e){for(var r=0;r<e.length;r++){var n=e[r];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,r,n){return r&&t(e.prototype,r),n&&t(e,n),e}}(),i=r(0);e.User=function(){function t(e){var r=e.id_token,n=e.session_state,i=e.access_token,o=e.refresh_token,s=e.token_type,a=e.scope,u=e.profile,c=e.expires_at,h=e.state;!function l(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}(this,t),this.id_token=r,this.session_state=n,this.access_token=i,this.refresh_token=o,this.token_type=s,this.scope=a,this.profile=u,this.expires_at=c,this.state=h}return t.prototype.toStorageString=function t(){return i.Log.debug("User.toStorageString"),JSON.stringify({id_token:this.id_token,session_state:this.session_state,access_token:this.access_token,refresh_token:this.refresh_token,token_type:this.token_type,scope:this.scope,profile:this.profile,expires_at:this.expires_at})},t.fromStorageString=function e(r){return i.Log.debug("User.fromStorageString"),new t(JSON.parse(r))},n(t,[{key:"expires_in",get:function t(){if(this.expires_at){var e=parseInt(Date.now()/1e3);return this.expires_at-e}},set:function t(e){var r=parseInt(e);if("number"==typeof r&&r>0){var n=parseInt(Date.now()/1e3);this.expires_at=n+r}}},{key:"expired",get:function t(){var e=this.expires_in;if(void 0!==e)return e<=0}},{key:"scopes",get:function t(){return(this.scope||"").split(" ")}}]),t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.AccessTokenEvents=void 0;var n=r(0),i=r(46);function o(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}e.AccessTokenEvents=function(){function t(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},r=e.accessTokenExpiringNotificationTime,n=void 0===r?60:r,s=e.accessTokenExpiringTimer,a=void 0===s?new i.Timer("Access token expiring"):s,u=e.accessTokenExpiredTimer,c=void 0===u?new i.Timer("Access token expired"):u;o(this,t),this._accessTokenExpiringNotificationTime=n,this._accessTokenExpiring=a,this._accessTokenExpired=c}return t.prototype.load=function t(e){if(e.access_token&&void 0!==e.expires_in){var r=e.expires_in;if(n.Log.debug("AccessTokenEvents.load: access token present, remaining duration:",r),r>0){var i=r-this._accessTokenExpiringNotificationTime;i<=0&&(i=1),n.Log.debug("AccessTokenEvents.load: registering expiring timer in:",i),this._accessTokenExpiring.init(i)}else n.Log.debug("AccessTokenEvents.load: canceling existing expiring timer becase we're past expiration."),this._accessTokenExpiring.cancel();var o=r+1;n.Log.debug("AccessTokenEvents.load: registering expired timer in:",o),this._accessTokenExpired.init(o)}else this._accessTokenExpiring.cancel(),this._accessTokenExpired.cancel()},t.prototype.unload=function t(){n.Log.debug("AccessTokenEvents.unload: canceling existing access token timers"),this._accessTokenExpiring.cancel(),this._accessTokenExpired.cancel()},t.prototype.addAccessTokenExpiring=function t(e){this._accessTokenExpiring.addHandler(e)},t.prototype.removeAccessTokenExpiring=function t(e){this._accessTokenExpiring.removeHandler(e)},t.prototype.addAccessTokenExpired=function t(e){this._accessTokenExpired.addHandler(e)},t.prototype.removeAccessTokenExpired=function t(e){this._accessTokenExpired.removeHandler(e)},t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.Event=void 0;var n=r(0);e.Event=function(){function t(e){!function r(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}(this,t),this._name=e,this._callbacks=[]}return t.prototype.addHandler=function t(e){this._callbacks.push(e)},t.prototype.removeHandler=function t(e){var r=this._callbacks.findIndex((function(t){return t===e}));r>=0&&this._callbacks.splice(r,1)},t.prototype.raise=function t(){n.Log.debug("Event: Raising event: "+this._name);for(var e=0;e<this._callbacks.length;e++){var r;(r=this._callbacks)[e].apply(r,arguments)}},t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.SessionMonitor=void 0;var n=function(){function t(t,e){for(var r=0;r<e.length;r++){var n=e[r];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,r,n){return r&&t(e.prototype,r),n&&t(e,n),e}}(),i=r(0),o=r(19),s=r(1);function a(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}e.SessionMonitor=function(){function t(e){var r=this,n=arguments.length>1&&void 0!==arguments[1]?arguments[1]:o.CheckSessionIFrame,u=arguments.length>2&&void 0!==arguments[2]?arguments[2]:s.Global.timer;if(a(this,t),!e)throw i.Log.error("SessionMonitor.ctor: No user manager passed to SessionMonitor"),new Error("userManager");this._userManager=e,this._CheckSessionIFrameCtor=n,this._timer=u,this._userManager.events.addUserLoaded(this._start.bind(this)),this._userManager.events.addUserUnloaded(this._stop.bind(this)),Promise.resolve(this._userManager.getUser().then((function(t){t?r._start(t):r._settings.monitorAnonymousSession&&r._userManager.querySessionStatus().then((function(t){var e={session_state:t.session_state};t.sub&&t.sid&&(e.profile={sub:t.sub,sid:t.sid}),r._start(e)})).catch((function(t){i.Log.error("SessionMonitor ctor: error from querySessionStatus:",t.message)}))})).catch((function(t){i.Log.error("SessionMonitor ctor: error from getUser:",t.message)})))}return t.prototype._start=function t(e){var r=this,n=e.session_state;n&&(e.profile?(this._sub=e.profile.sub,this._sid=e.profile.sid,i.Log.debug("SessionMonitor._start: session_state:",n,", sub:",this._sub)):(this._sub=void 0,this._sid=void 0,i.Log.debug("SessionMonitor._start: session_state:",n,", anonymous user")),this._checkSessionIFrame?this._checkSessionIFrame.start(n):this._metadataService.getCheckSessionIframe().then((function(t){if(t){i.Log.debug("SessionMonitor._start: Initializing check session iframe");var e=r._client_id,o=r._checkSessionInterval,s=r._stopCheckSessionOnError;r._checkSessionIFrame=new r._CheckSessionIFrameCtor(r._callback.bind(r),e,t,o,s),r._checkSessionIFrame.load().then((function(){r._checkSessionIFrame.start(n)}))}else i.Log.warn("SessionMonitor._start: No check session iframe found in the metadata")})).catch((function(t){i.Log.error("SessionMonitor._start: Error from getCheckSessionIframe:",t.message)})))},t.prototype._stop=function t(){var e=this;if(this._sub=void 0,this._sid=void 0,this._checkSessionIFrame&&(i.Log.debug("SessionMonitor._stop"),this._checkSessionIFrame.stop()),this._settings.monitorAnonymousSession)var r=this._timer.setInterval((function(){e._timer.clearInterval(r),e._userManager.querySessionStatus().then((function(t){var r={session_state:t.session_state};t.sub&&t.sid&&(r.profile={sub:t.sub,sid:t.sid}),e._start(r)})).catch((function(t){i.Log.error("SessionMonitor: error from querySessionStatus:",t.message)}))}),1e3)},t.prototype._callback=function t(){var e=this;this._userManager.querySessionStatus().then((function(t){var r=!0;t?t.sub===e._sub?(r=!1,e._checkSessionIFrame.start(t.session_state),t.sid===e._sid?i.Log.debug("SessionMonitor._callback: Same sub still logged in at OP, restarting check session iframe; session_state:",t.session_state):(i.Log.debug("SessionMonitor._callback: Same sub still logged in at OP, session state has changed, restarting check session iframe; session_state:",t.session_state),e._userManager.events._raiseUserSessionChanged())):i.Log.debug("SessionMonitor._callback: Different subject signed into OP:",t.sub):i.Log.debug("SessionMonitor._callback: Subject no longer signed into OP"),r&&(e._sub?(i.Log.debug("SessionMonitor._callback: SessionMonitor._callback; raising signed out event"),e._userManager.events._raiseUserSignedOut()):(i.Log.debug("SessionMonitor._callback: SessionMonitor._callback; raising signed in event"),e._userManager.events._raiseUserSignedIn()))})).catch((function(t){e._sub&&(i.Log.debug("SessionMonitor._callback: Error calling queryCurrentSigninSession; raising signed out event",t.message),e._userManager.events._raiseUserSignedOut())}))},n(t,[{key:"_settings",get:function t(){return this._userManager.settings}},{key:"_metadataService",get:function t(){return this._userManager.metadataService}},{key:"_client_id",get:function t(){return this._settings.client_id}},{key:"_checkSessionInterval",get:function t(){return this._settings.checkSessionInterval}},{key:"_stopCheckSessionOnError",get:function t(){return this._settings.stopCheckSessionOnError}}]),t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.CheckSessionIFrame=void 0;var n=r(0);function i(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}e.CheckSessionIFrame=function(){function t(e,r,n,o){var s=!(arguments.length>4&&void 0!==arguments[4])||arguments[4];i(this,t),this._callback=e,this._client_id=r,this._url=n,this._interval=o||2e3,this._stopOnError=s;var a=n.indexOf("/",n.indexOf("//")+2);this._frame_origin=n.substr(0,a),this._frame=window.document.createElement("iframe"),this._frame.style.visibility="hidden",this._frame.style.position="absolute",this._frame.style.display="none",this._frame.width=0,this._frame.height=0,this._frame.src=n}return t.prototype.load=function t(){var e=this;return new Promise((function(t){e._frame.onload=function(){t()},window.document.body.appendChild(e._frame),e._boundMessageEvent=e._message.bind(e),window.addEventListener("message",e._boundMessageEvent,!1)}))},t.prototype._message=function t(e){e.origin===this._frame_origin&&e.source===this._frame.contentWindow&&("error"===e.data?(n.Log.error("CheckSessionIFrame: error message from check session op iframe"),this._stopOnError&&this.stop()):"changed"===e.data?(n.Log.debug("CheckSessionIFrame: changed message from check session op iframe"),this.stop(),this._callback()):n.Log.debug("CheckSessionIFrame: "+e.data+" message from check session op iframe"))},t.prototype.start=function t(e){var r=this;if(this._session_state!==e){n.Log.debug("CheckSessionIFrame.start"),this.stop(),this._session_state=e;var i=function t(){r._frame.contentWindow.postMessage(r._client_id+" "+r._session_state,r._frame_origin)};i(),this._timer=window.setInterval(i,this._interval)}},t.prototype.stop=function t(){this._session_state=null,this._timer&&(n.Log.debug("CheckSessionIFrame.stop"),window.clearInterval(this._timer),this._timer=null)},t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.TokenRevocationClient=void 0;var n=r(0),i=r(2),o=r(1);function s(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}var a="access_token",u="refresh_token";e.TokenRevocationClient=function(){function t(e){var r=arguments.length>1&&void 0!==arguments[1]?arguments[1]:o.Global.XMLHttpRequest,a=arguments.length>2&&void 0!==arguments[2]?arguments[2]:i.MetadataService;if(s(this,t),!e)throw n.Log.error("TokenRevocationClient.ctor: No settings provided"),new Error("No settings provided.");this._settings=e,this._XMLHttpRequestCtor=r,this._metadataService=new a(this._settings)}return t.prototype.revoke=function t(e,r){var i=this,o=arguments.length>2&&void 0!==arguments[2]?arguments[2]:"access_token";if(!e)throw n.Log.error("TokenRevocationClient.revoke: No token provided"),new Error("No token provided.");if(o!==a&&o!=u)throw n.Log.error("TokenRevocationClient.revoke: Invalid token type"),new Error("Invalid token type.");return this._metadataService.getRevocationEndpoint().then((function(t){if(t){n.Log.debug("TokenRevocationClient.revoke: Revoking "+o);var s=i._settings.client_id,a=i._settings.client_secret;return i._revoke(t,s,a,e,o)}if(r)throw n.Log.error("TokenRevocationClient.revoke: Revocation not supported"),new Error("Revocation not supported")}))},t.prototype._revoke=function t(e,r,i,o,s){var a=this;return new Promise((function(t,u){var c=new a._XMLHttpRequestCtor;c.open("POST",e),c.onload=function(){n.Log.debug("TokenRevocationClient.revoke: HTTP response received, status",c.status),200===c.status?t():u(Error(c.statusText+" ("+c.status+")"))},c.onerror=function(){n.Log.debug("TokenRevocationClient.revoke: Network Error."),u("Network Error")};var h="client_id="+encodeURIComponent(r);i&&(h+="&client_secret="+encodeURIComponent(i)),h+="&token_type_hint="+encodeURIComponent(s),h+="&token="+encodeURIComponent(o),c.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),c.send(h)}))},t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.CordovaPopupWindow=void 0;var n=function(){function t(t,e){for(var r=0;r<e.length;r++){var n=e[r];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,r,n){return r&&t(e.prototype,r),n&&t(e,n),e}}(),i=r(0);e.CordovaPopupWindow=function(){function t(e){var r=this;!function n(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}(this,t),this._promise=new Promise((function(t,e){r._resolve=t,r._reject=e})),this.features=e.popupWindowFeatures||"location=no,toolbar=no,zoom=no",this.target=e.popupWindowTarget||"_blank",this.redirect_uri=e.startUrl,i.Log.debug("CordovaPopupWindow.ctor: redirect_uri: "+this.redirect_uri)}return t.prototype._isInAppBrowserInstalled=function t(e){return["cordova-plugin-inappbrowser","cordova-plugin-inappbrowser.inappbrowser","org.apache.cordova.inappbrowser"].some((function(t){return e.hasOwnProperty(t)}))},t.prototype.navigate=function t(e){if(e&&e.url){if(!window.cordova)return this._error("cordova is undefined");var r=window.cordova.require("cordova/plugin_list").metadata;if(!1===this._isInAppBrowserInstalled(r))return this._error("InAppBrowser plugin not found");this._popup=cordova.InAppBrowser.open(e.url,this.target,this.features),this._popup?(i.Log.debug("CordovaPopupWindow.navigate: popup successfully created"),this._exitCallbackEvent=this._exitCallback.bind(this),this._loadStartCallbackEvent=this._loadStartCallback.bind(this),this._popup.addEventListener("exit",this._exitCallbackEvent,!1),this._popup.addEventListener("loadstart",this._loadStartCallbackEvent,!1)):this._error("Error opening popup window")}else this._error("No url provided");return this.promise},t.prototype._loadStartCallback=function t(e){0===e.url.indexOf(this.redirect_uri)&&this._success({url:e.url})},t.prototype._exitCallback=function t(e){this._error(e)},t.prototype._success=function t(e){this._cleanup(),i.Log.debug("CordovaPopupWindow: Successful response from cordova popup window"),this._resolve(e)},t.prototype._error=function t(e){this._cleanup(),i.Log.error(e),this._reject(new Error(e))},t.prototype.close=function t(){this._cleanup()},t.prototype._cleanup=function t(){this._popup&&(i.Log.debug("CordovaPopupWindow: cleaning up popup"),this._popup.removeEventListener("exit",this._exitCallbackEvent,!1),this._popup.removeEventListener("loadstart",this._loadStartCallbackEvent,!1),this._popup.close()),this._popup=null},n(t,[{key:"promise",get:function t(){return this._promise}}]),t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0});var n=r(0),i=r(10),o=r(5),s=r(6),a=r(37),u=r(38),c=r(16),h=r(2),l=r(48),f=r(49),g=r(19),d=r(20),p=r(18),v=r(1),y=r(15),m=r(50);e.default={Version:m.Version,Log:n.Log,OidcClient:i.OidcClient,OidcClientSettings:o.OidcClientSettings,WebStorageStateStore:s.WebStorageStateStore,InMemoryWebStorage:a.InMemoryWebStorage,UserManager:u.UserManager,AccessTokenEvents:c.AccessTokenEvents,MetadataService:h.MetadataService,CordovaPopupNavigator:l.CordovaPopupNavigator,CordovaIFrameNavigator:f.CordovaIFrameNavigator,CheckSessionIFrame:g.CheckSessionIFrame,TokenRevocationClient:d.TokenRevocationClient,SessionMonitor:p.SessionMonitor,Global:v.Global,User:y.User},t.exports=e.default},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0});e.ClockService=function(){function t(){!function e(t,r){if(!(t instanceof r))throw new TypeError("Cannot call a class as a function")}(this,t)}return t.prototype.getEpochTime=function t(){return Promise.resolve(Date.now()/1e3|0)},t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.ResponseValidator=void 0;var n="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(t){return typeof t}:function(t){return t&&"function"==typeof Symbol&&t.constructor===Symbol&&t!==Symbol.prototype?"symbol":typeof t},i=r(0),o=r(2),s=r(25),a=r(11),u=r(12),c=r(4);function h(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}var l=["nonce","at_hash","iat","nbf","exp","aud","iss","c_hash"];e.ResponseValidator=function(){function t(e){var r=arguments.length>1&&void 0!==arguments[1]?arguments[1]:o.MetadataService,n=arguments.length>2&&void 0!==arguments[2]?arguments[2]:s.UserInfoService,u=arguments.length>3&&void 0!==arguments[3]?arguments[3]:c.JoseUtil,l=arguments.length>4&&void 0!==arguments[4]?arguments[4]:a.TokenClient;if(h(this,t),!e)throw i.Log.error("ResponseValidator.ctor: No settings passed to ResponseValidator"),new Error("settings");this._settings=e,this._metadataService=new r(this._settings),this._userInfoService=new n(this._settings),this._joseUtil=u,this._tokenClient=new l(this._settings)}return t.prototype.validateSigninResponse=function t(e,r){var n=this;return i.Log.debug("ResponseValidator.validateSigninResponse"),this._processSigninParams(e,r).then((function(t){return i.Log.debug("ResponseValidator.validateSigninResponse: state processed"),n._validateTokens(e,t).then((function(t){return i.Log.debug("ResponseValidator.validateSigninResponse: tokens validated"),n._processClaims(e,t).then((function(t){return i.Log.debug("ResponseValidator.validateSigninResponse: claims processed"),t}))}))}))},t.prototype.validateSignoutResponse=function t(e,r){return e.id!==r.state?(i.Log.error("ResponseValidator.validateSignoutResponse: State does not match"),Promise.reject(new Error("State does not match"))):(i.Log.debug("ResponseValidator.validateSignoutResponse: state validated"),r.state=e.data,r.error?(i.Log.warn("ResponseValidator.validateSignoutResponse: Response was error",r.error),Promise.reject(new u.ErrorResponse(r))):Promise.resolve(r))},t.prototype._processSigninParams=function t(e,r){if(e.id!==r.state)return i.Log.error("ResponseValidator._processSigninParams: State does not match"),Promise.reject(new Error("State does not match"));if(!e.client_id)return i.Log.error("ResponseValidator._processSigninParams: No client_id on state"),Promise.reject(new Error("No client_id on state"));if(!e.authority)return i.Log.error("ResponseValidator._processSigninParams: No authority on state"),Promise.reject(new Error("No authority on state"));if(this._settings.authority){if(this._settings.authority&&this._settings.authority!==e.authority)return i.Log.error("ResponseValidator._processSigninParams: authority mismatch on settings vs. signin state"),Promise.reject(new Error("authority mismatch on settings vs. signin state"))}else this._settings.authority=e.authority;if(this._settings.client_id){if(this._settings.client_id&&this._settings.client_id!==e.client_id)return i.Log.error("ResponseValidator._processSigninParams: client_id mismatch on settings vs. signin state"),Promise.reject(new Error("client_id mismatch on settings vs. signin state"))}else this._settings.client_id=e.client_id;return i.Log.debug("ResponseValidator._processSigninParams: state validated"),r.state=e.data,r.error?(i.Log.warn("ResponseValidator._processSigninParams: Response was error",r.error),Promise.reject(new u.ErrorResponse(r))):e.nonce&&!r.id_token?(i.Log.error("ResponseValidator._processSigninParams: Expecting id_token in response"),Promise.reject(new Error("No id_token in response"))):!e.nonce&&r.id_token?(i.Log.error("ResponseValidator._processSigninParams: Not expecting id_token in response"),Promise.reject(new Error("Unexpected id_token in response"))):e.code_verifier&&!r.code?(i.Log.error("ResponseValidator._processSigninParams: Expecting code in response"),Promise.reject(new Error("No code in response"))):!e.code_verifier&&r.code?(i.Log.error("ResponseValidator._processSigninParams: Not expecting code in response"),Promise.reject(new Error("Unexpected code in response"))):(r.scope||(r.scope=e.scope),Promise.resolve(r))},t.prototype._processClaims=function t(e,r){var n=this;if(r.isOpenIdConnect){if(i.Log.debug("ResponseValidator._processClaims: response is OIDC, processing claims"),r.profile=this._filterProtocolClaims(r.profile),!0!==e.skipUserInfo&&this._settings.loadUserInfo&&r.access_token)return i.Log.debug("ResponseValidator._processClaims: loading user info"),this._userInfoService.getClaims(r.access_token).then((function(t){return i.Log.debug("ResponseValidator._processClaims: user info claims received from user info endpoint"),t.sub!==r.profile.sub?(i.Log.error("ResponseValidator._processClaims: sub from user info endpoint does not match sub in id_token"),Promise.reject(new Error("sub from user info endpoint does not match sub in id_token"))):(r.profile=n._mergeClaims(r.profile,t),i.Log.debug("ResponseValidator._processClaims: user info claims received, updated profile:",r.profile),r)}));i.Log.debug("ResponseValidator._processClaims: not loading user info")}else i.Log.debug("ResponseValidator._processClaims: response is not OIDC, not processing claims");return Promise.resolve(r)},t.prototype._mergeClaims=function t(e,r){var i=Object.assign({},e);for(var o in r){var s=r[o];Array.isArray(s)||(s=[s]);for(var a=0;a<s.length;a++){var u=s[a];i[o]?Array.isArray(i[o])?i[o].indexOf(u)<0&&i[o].push(u):i[o]!==u&&("object"===(void 0===u?"undefined":n(u))&&this._settings.mergeClaims?i[o]=this._mergeClaims(i[o],u):i[o]=[i[o],u]):i[o]=u}}return i},t.prototype._filterProtocolClaims=function t(e){i.Log.debug("ResponseValidator._filterProtocolClaims, incoming claims:",e);var r=Object.assign({},e);return this._settings._filterProtocolClaims?(l.forEach((function(t){delete r[t]})),i.Log.debug("ResponseValidator._filterProtocolClaims: protocol claims filtered",r)):i.Log.debug("ResponseValidator._filterProtocolClaims: protocol claims not filtered"),r},t.prototype._validateTokens=function t(e,r){return r.code?(i.Log.debug("ResponseValidator._validateTokens: Validating code"),this._processCode(e,r)):r.id_token?r.access_token?(i.Log.debug("ResponseValidator._validateTokens: Validating id_token and access_token"),this._validateIdTokenAndAccessToken(e,r)):(i.Log.debug("ResponseValidator._validateTokens: Validating id_token"),this._validateIdToken(e,r)):(i.Log.debug("ResponseValidator._validateTokens: No code to process or id_token to validate"),Promise.resolve(r))},t.prototype._processCode=function t(e,r){var o=this,s={client_id:e.client_id,client_secret:e.client_secret,code:r.code,redirect_uri:e.redirect_uri,code_verifier:e.code_verifier};return e.extraTokenParams&&"object"===n(e.extraTokenParams)&&Object.assign(s,e.extraTokenParams),this._tokenClient.exchangeCode(s).then((function(t){for(var n in t)r[n]=t[n];return r.id_token?(i.Log.debug("ResponseValidator._processCode: token response successful, processing id_token"),o._validateIdTokenAttributes(e,r)):(i.Log.debug("ResponseValidator._processCode: token response successful, returning response"),r)}))},t.prototype._validateIdTokenAttributes=function t(e,r){var n=this;return this._metadataService.getIssuer().then((function(t){var o=e.client_id,s=n._settings.clockSkew;return i.Log.debug("ResponseValidator._validateIdTokenAttributes: Validaing JWT attributes; using clock skew (in seconds) of: ",s),n._settings.getEpochTime().then((function(a){return n._joseUtil.validateJwtAttributes(r.id_token,t,o,s,a).then((function(t){return e.nonce&&e.nonce!==t.nonce?(i.Log.error("ResponseValidator._validateIdTokenAttributes: Invalid nonce in id_token"),Promise.reject(new Error("Invalid nonce in id_token"))):t.sub?(r.profile=t,r):(i.Log.error("ResponseValidator._validateIdTokenAttributes: No sub present in id_token"),Promise.reject(new Error("No sub present in id_token")))}))}))}))},t.prototype._validateIdTokenAndAccessToken=function t(e,r){var n=this;return this._validateIdToken(e,r).then((function(t){return n._validateAccessToken(t)}))},t.prototype._getSigningKeyForJwt=function t(e){var r=this;return this._metadataService.getSigningKeys().then((function(t){var n=e.header.kid;if(!t)return i.Log.error("ResponseValidator._validateIdToken: No signing keys from metadata"),Promise.reject(new Error("No signing keys from metadata"));i.Log.debug("ResponseValidator._validateIdToken: Received signing keys");var o=void 0;if(n)o=t.filter((function(t){return t.kid===n}))[0];else{if((t=r._filterByAlg(t,e.header.alg)).length>1)return i.Log.error("ResponseValidator._validateIdToken: No kid found in id_token and more than one key found in metadata"),Promise.reject(new Error("No kid found in id_token and more than one key found in metadata"));o=t[0]}return Promise.resolve(o)}))},t.prototype._getSigningKeyForJwtWithSingleRetry=function t(e){var r=this;return this._getSigningKeyForJwt(e).then((function(t){return t?Promise.resolve(t):(r._metadataService.resetSigningKeys(),r._getSigningKeyForJwt(e))}))},t.prototype._validateIdToken=function t(e,r){var n=this;if(!e.nonce)return i.Log.error("ResponseValidator._validateIdToken: No nonce on state"),Promise.reject(new Error("No nonce on state"));var o=this._joseUtil.parseJwt(r.id_token);return o&&o.header&&o.payload?e.nonce!==o.payload.nonce?(i.Log.error("ResponseValidator._validateIdToken: Invalid nonce in id_token"),Promise.reject(new Error("Invalid nonce in id_token"))):this._metadataService.getIssuer().then((function(t){return i.Log.debug("ResponseValidator._validateIdToken: Received issuer"),n._getSigningKeyForJwtWithSingleRetry(o).then((function(s){if(!s)return i.Log.error("ResponseValidator._validateIdToken: No key matching kid or alg found in signing keys"),Promise.reject(new Error("No key matching kid or alg found in signing keys"));var a=e.client_id,u=n._settings.clockSkew;return i.Log.debug("ResponseValidator._validateIdToken: Validaing JWT; using clock skew (in seconds) of: ",u),n._joseUtil.validateJwt(r.id_token,s,t,a,u).then((function(){return i.Log.debug("ResponseValidator._validateIdToken: JWT validation successful"),o.payload.sub?(r.profile=o.payload,r):(i.Log.error("ResponseValidator._validateIdToken: No sub present in id_token"),Promise.reject(new Error("No sub present in id_token")))}))}))})):(i.Log.error("ResponseValidator._validateIdToken: Failed to parse id_token",o),Promise.reject(new Error("Failed to parse id_token")))},t.prototype._filterByAlg=function t(e,r){var n=null;if(r.startsWith("RS"))n="RSA";else if(r.startsWith("PS"))n="PS";else{if(!r.startsWith("ES"))return i.Log.debug("ResponseValidator._filterByAlg: alg not supported: ",r),[];n="EC"}return i.Log.debug("ResponseValidator._filterByAlg: Looking for keys that match kty: ",n),e=e.filter((function(t){return t.kty===n})),i.Log.debug("ResponseValidator._filterByAlg: Number of keys that match kty: ",n,e.length),e},t.prototype._validateAccessToken=function t(e){if(!e.profile)return i.Log.error("ResponseValidator._validateAccessToken: No profile loaded from id_token"),Promise.reject(new Error("No profile loaded from id_token"));if(!e.profile.at_hash)return i.Log.error("ResponseValidator._validateAccessToken: No at_hash in id_token"),Promise.reject(new Error("No at_hash in id_token"));if(!e.id_token)return i.Log.error("ResponseValidator._validateAccessToken: No id_token"),Promise.reject(new Error("No id_token"));var r=this._joseUtil.parseJwt(e.id_token);if(!r||!r.header)return i.Log.error("ResponseValidator._validateAccessToken: Failed to parse id_token",r),Promise.reject(new Error("Failed to parse id_token"));var n=r.header.alg;if(!n||5!==n.length)return i.Log.error("ResponseValidator._validateAccessToken: Unsupported alg:",n),Promise.reject(new Error("Unsupported alg: "+n));var o=n.substr(2,3);if(!o)return i.Log.error("ResponseValidator._validateAccessToken: Unsupported alg:",n,o),Promise.reject(new Error("Unsupported alg: "+n));if(256!==(o=parseInt(o))&&384!==o&&512!==o)return i.Log.error("ResponseValidator._validateAccessToken: Unsupported alg:",n,o),Promise.reject(new Error("Unsupported alg: "+n));var s="sha"+o,a=this._joseUtil.hashString(e.access_token,s);if(!a)return i.Log.error("ResponseValidator._validateAccessToken: access_token hash failed:",s),Promise.reject(new Error("Failed to validate at_hash"));var u=a.substr(0,a.length/2),c=this._joseUtil.hexToBase64Url(u);return c!==e.profile.at_hash?(i.Log.error("ResponseValidator._validateAccessToken: Failed to validate at_hash",c,e.profile.at_hash),Promise.reject(new Error("Failed to validate at_hash"))):(i.Log.debug("ResponseValidator._validateAccessToken: success"),Promise.resolve(e))},t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.UserInfoService=void 0;var n=r(7),i=r(2),o=r(0),s=r(4);function a(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}e.UserInfoService=function(){function t(e){var r=arguments.length>1&&void 0!==arguments[1]?arguments[1]:n.JsonService,u=arguments.length>2&&void 0!==arguments[2]?arguments[2]:i.MetadataService,c=arguments.length>3&&void 0!==arguments[3]?arguments[3]:s.JoseUtil;if(a(this,t),!e)throw o.Log.error("UserInfoService.ctor: No settings passed"),new Error("settings");this._settings=e,this._jsonService=new r(void 0,void 0,this._getClaimsFromJwt.bind(this)),this._metadataService=new u(this._settings),this._joseUtil=c}return t.prototype.getClaims=function t(e){var r=this;return e?this._metadataService.getUserInfoEndpoint().then((function(t){return o.Log.debug("UserInfoService.getClaims: received userinfo url",t),r._jsonService.getJson(t,e).then((function(t){return o.Log.debug("UserInfoService.getClaims: claims received",t),t}))})):(o.Log.error("UserInfoService.getClaims: No token passed"),Promise.reject(new Error("A token is required")))},t.prototype._getClaimsFromJwt=function t(e){var r=this;try{var n=this._joseUtil.parseJwt(e.responseText);if(!n||!n.header||!n.payload)return o.Log.error("UserInfoService._getClaimsFromJwt: Failed to parse JWT",n),Promise.reject(new Error("Failed to parse id_token"));var i=n.header.kid,s=void 0;switch(this._settings.userInfoJwtIssuer){case"OP":s=this._metadataService.getIssuer();break;case"ANY":s=Promise.resolve(n.payload.iss);break;default:s=Promise.resolve(this._settings.userInfoJwtIssuer)}return s.then((function(t){return o.Log.debug("UserInfoService._getClaimsFromJwt: Received issuer:"+t),r._metadataService.getSigningKeys().then((function(s){if(!s)return o.Log.error("UserInfoService._getClaimsFromJwt: No signing keys from metadata"),Promise.reject(new Error("No signing keys from metadata"));o.Log.debug("UserInfoService._getClaimsFromJwt: Received signing keys");var a=void 0;if(i)a=s.filter((function(t){return t.kid===i}))[0];else{if((s=r._filterByAlg(s,n.header.alg)).length>1)return o.Log.error("UserInfoService._getClaimsFromJwt: No kid found in id_token and more than one key found in metadata"),Promise.reject(new Error("No kid found in id_token and more than one key found in metadata"));a=s[0]}if(!a)return o.Log.error("UserInfoService._getClaimsFromJwt: No key matching kid or alg found in signing keys"),Promise.reject(new Error("No key matching kid or alg found in signing keys"));var u=r._settings.client_id,c=r._settings.clockSkew;return o.Log.debug("UserInfoService._getClaimsFromJwt: Validaing JWT; using clock skew (in seconds) of: ",c),r._joseUtil.validateJwt(e.responseText,a,t,u,c,void 0,!0).then((function(){return o.Log.debug("UserInfoService._getClaimsFromJwt: JWT validation successful"),n.payload}))}))}))}catch(t){return o.Log.error("UserInfoService._getClaimsFromJwt: Error parsing JWT response",t.message),void reject(t)}},t.prototype._filterByAlg=function t(e,r){var n=null;if(r.startsWith("RS"))n="RSA";else if(r.startsWith("PS"))n="PS";else{if(!r.startsWith("ES"))return o.Log.debug("UserInfoService._filterByAlg: alg not supported: ",r),[];n="EC"}return o.Log.debug("UserInfoService._filterByAlg: Looking for keys that match kty: ",n),e=e.filter((function(t){return t.kty===n})),o.Log.debug("UserInfoService._filterByAlg: Number of keys that match kty: ",n,e.length),e},t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.AllowedSigningAlgs=e.b64tohex=e.hextob64u=e.crypto=e.X509=e.KeyUtil=e.jws=void 0;var n=r(27);e.jws=n.jws,e.KeyUtil=n.KEYUTIL,e.X509=n.X509,e.crypto=n.crypto,e.hextob64u=n.hextob64u,e.b64tohex=n.b64tohex,e.AllowedSigningAlgs=["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES384","ES512"]},function(t,e,r){"use strict";(function(t){Object.defineProperty(e,"__esModule",{value:!0});var r,n,i,o,s,a,u,c,h,l,f,g="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(t){return typeof t}:function(t){return t&&"function"==typeof Symbol&&t.constructor===Symbol&&t!==Symbol.prototype?"symbol":typeof t},d={userAgent:!1},p={},v=v||(r=Math,i=(n={}).lib={},o=i.Base=function(){function t(){}return{extend:function e(r){t.prototype=this;var n=new t;return r&&n.mixIn(r),n.hasOwnProperty("init")||(n.init=function(){n.$super.init.apply(this,arguments)}),n.init.prototype=n,n.$super=this,n},create:function t(){var e=this.extend();return e.init.apply(e,arguments),e},init:function t(){},mixIn:function t(e){for(var r in e)e.hasOwnProperty(r)&&(this[r]=e[r]);e.hasOwnProperty("toString")&&(this.toString=e.toString)},clone:function t(){return this.init.prototype.extend(this)}}}(),s=i.WordArray=o.extend({init:function t(e,r){e=this.words=e||[],this.sigBytes=null!=r?r:4*e.length},toString:function t(e){return(e||u).stringify(this)},concat:function t(e){var r=this.words,n=e.words,i=this.sigBytes,o=e.sigBytes;if(this.clamp(),i%4)for(var s=0;s<o;s++){var a=n[s>>>2]>>>24-s%4*8&255;r[i+s>>>2]|=a<<24-(i+s)%4*8}else for(s=0;s<o;s+=4)r[i+s>>>2]=n[s>>>2];return this.sigBytes+=o,this},clamp:function t(){var e=this.words,n=this.sigBytes;e[n>>>2]&=4294967295<<32-n%4*8,e.length=r.ceil(n/4)},clone:function t(){var e=o.clone.call(this);return e.words=this.words.slice(0),e},random:function t(e){for(var n=[],i=0;i<e;i+=4)n.push(4294967296*r.random()|0);return new s.init(n,e)}}),a=n.enc={},u=a.Hex={stringify:function t(e){for(var r=e.words,n=e.sigBytes,i=[],o=0;o<n;o++){var s=r[o>>>2]>>>24-o%4*8&255;i.push((s>>>4).toString(16)),i.push((15&s).toString(16))}return i.join("")},parse:function t(e){for(var r=e.length,n=[],i=0;i<r;i+=2)n[i>>>3]|=parseInt(e.substr(i,2),16)<<24-i%8*4;return new s.init(n,r/2)}},c=a.Latin1={stringify:function t(e){for(var r=e.words,n=e.sigBytes,i=[],o=0;o<n;o++){var s=r[o>>>2]>>>24-o%4*8&255;i.push(String.fromCharCode(s))}return i.join("")},parse:function t(e){for(var r=e.length,n=[],i=0;i<r;i++)n[i>>>2]|=(255&e.charCodeAt(i))<<24-i%4*8;return new s.init(n,r)}},h=a.Utf8={stringify:function t(e){try{return decodeURIComponent(escape(c.stringify(e)))}catch(t){throw new Error("Malformed UTF-8 data")}},parse:function t(e){return c.parse(unescape(encodeURIComponent(e)))}},l=i.BufferedBlockAlgorithm=o.extend({reset:function t(){this._data=new s.init,this._nDataBytes=0},_append:function t(e){"string"==typeof e&&(e=h.parse(e)),this._data.concat(e),this._nDataBytes+=e.sigBytes},_process:function t(e){var n=this._data,i=n.words,o=n.sigBytes,a=this.blockSize,u=o/(4*a),c=(u=e?r.ceil(u):r.max((0|u)-this._minBufferSize,0))*a,h=r.min(4*c,o);if(c){for(var l=0;l<c;l+=a)this._doProcessBlock(i,l);var f=i.splice(0,c);n.sigBytes-=h}return new s.init(f,h)},clone:function t(){var e=o.clone.call(this);return e._data=this._data.clone(),e},_minBufferSize:0}),i.Hasher=l.extend({cfg:o.extend(),init:function t(e){this.cfg=this.cfg.extend(e),this.reset()},reset:function t(){l.reset.call(this),this._doReset()},update:function t(e){return this._append(e),this._process(),this},finalize:function t(e){return e&&this._append(e),this._doFinalize()},blockSize:16,_createHelper:function t(e){return function(t,r){return new e.init(r).finalize(t)}},_createHmacHelper:function t(e){return function(t,r){return new f.HMAC.init(e,r).finalize(t)}}}),f=n.algo={},n);!function(t){var e,r=(e=v).lib,n=r.Base,i=r.WordArray;(e=e.x64={}).Word=n.extend({init:function t(e,r){this.high=e,this.low=r}}),e.WordArray=n.extend({init:function t(e,r){e=this.words=e||[],this.sigBytes=null!=r?r:8*e.length},toX32:function t(){for(var e=this.words,r=e.length,n=[],o=0;o<r;o++){var s=e[o];n.push(s.high),n.push(s.low)}return i.create(n,this.sigBytes)},clone:function t(){for(var e=n.clone.call(this),r=e.words=this.words.slice(0),i=r.length,o=0;o<i;o++)r[o]=r[o].clone();return e}})}(),function(){var t=v,e=t.lib.WordArray;t.enc.Base64={stringify:function t(e){var r=e.words,n=e.sigBytes,i=this._map;e.clamp(),e=[];for(var o=0;o<n;o+=3)for(var s=(r[o>>>2]>>>24-o%4*8&255)<<16|(r[o+1>>>2]>>>24-(o+1)%4*8&255)<<8|r[o+2>>>2]>>>24-(o+2)%4*8&255,a=0;4>a&&o+.75*a<n;a++)e.push(i.charAt(s>>>6*(3-a)&63));if(r=i.charAt(64))for(;e.length%4;)e.push(r);return e.join("")},parse:function t(r){var n=r.length,i=this._map;(o=i.charAt(64))&&(-1!=(o=r.indexOf(o))&&(n=o));for(var o=[],s=0,a=0;a<n;a++)if(a%4){var u=i.indexOf(r.charAt(a-1))<<a%4*2,c=i.indexOf(r.charAt(a))>>>6-a%4*2;o[s>>>2]|=(u|c)<<24-s%4*8,s++}return e.create(o,s)},_map:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="}}(),function(t){for(var e=v,r=(i=e.lib).WordArray,n=i.Hasher,i=e.algo,o=[],s=[],a=function t(e){return 4294967296*(e-(0|e))|0},u=2,c=0;64>c;){var h;t:{h=u;for(var l=t.sqrt(h),f=2;f<=l;f++)if(!(h%f)){h=!1;break t}h=!0}h&&(8>c&&(o[c]=a(t.pow(u,.5))),s[c]=a(t.pow(u,1/3)),c++),u++}var g=[];i=i.SHA256=n.extend({_doReset:function t(){this._hash=new r.init(o.slice(0))},_doProcessBlock:function t(e,r){for(var n=this._hash.words,i=n[0],o=n[1],a=n[2],u=n[3],c=n[4],h=n[5],l=n[6],f=n[7],d=0;64>d;d++){if(16>d)g[d]=0|e[r+d];else{var p=g[d-15],v=g[d-2];g[d]=((p<<25|p>>>7)^(p<<14|p>>>18)^p>>>3)+g[d-7]+((v<<15|v>>>17)^(v<<13|v>>>19)^v>>>10)+g[d-16]}p=f+((c<<26|c>>>6)^(c<<21|c>>>11)^(c<<7|c>>>25))+(c&h^~c&l)+s[d]+g[d],v=((i<<30|i>>>2)^(i<<19|i>>>13)^(i<<10|i>>>22))+(i&o^i&a^o&a),f=l,l=h,h=c,c=u+p|0,u=a,a=o,o=i,i=p+v|0}n[0]=n[0]+i|0,n[1]=n[1]+o|0,n[2]=n[2]+a|0,n[3]=n[3]+u|0,n[4]=n[4]+c|0,n[5]=n[5]+h|0,n[6]=n[6]+l|0,n[7]=n[7]+f|0},_doFinalize:function e(){var r=this._data,n=r.words,i=8*this._nDataBytes,o=8*r.sigBytes;return n[o>>>5]|=128<<24-o%32,n[14+(o+64>>>9<<4)]=t.floor(i/4294967296),n[15+(o+64>>>9<<4)]=i,r.sigBytes=4*n.length,this._process(),this._hash},clone:function t(){var e=n.clone.call(this);return e._hash=this._hash.clone(),e}});e.SHA256=n._createHelper(i),e.HmacSHA256=n._createHmacHelper(i)}(Math),function(){function t(){return n.create.apply(n,arguments)}for(var e=v,r=e.lib.Hasher,n=(o=e.x64).Word,i=o.WordArray,o=e.algo,s=[t(1116352408,3609767458),t(1899447441,602891725),t(3049323471,3964484399),t(3921009573,2173295548),t(961987163,4081628472),t(1508970993,3053834265),t(2453635748,2937671579),t(2870763221,3664609560),t(3624381080,2734883394),t(310598401,1164996542),t(607225278,1323610764),t(1426881987,3590304994),t(1925078388,4068182383),t(2162078206,991336113),t(2614888103,633803317),t(3248222580,3479774868),t(3835390401,2666613458),t(4022224774,944711139),t(264347078,2341262773),t(604807628,2007800933),t(770255983,1495990901),t(1249150122,1856431235),t(1555081692,3175218132),t(1996064986,2198950837),t(2554220882,3999719339),t(2821834349,766784016),t(2952996808,2566594879),t(3210313671,3203337956),t(3336571891,1034457026),t(3584528711,2466948901),t(113926993,3758326383),t(338241895,168717936),t(666307205,1188179964),t(773529912,1546045734),t(1294757372,1522805485),t(1396182291,2643833823),t(1695183700,2343527390),t(1986661051,1014477480),t(2177026350,1206759142),t(2456956037,344077627),t(2730485921,1290863460),t(2820302411,3158454273),t(3259730800,3505952657),t(3345764771,106217008),t(3516065817,3606008344),t(3600352804,1432725776),t(4094571909,1467031594),t(275423344,851169720),t(430227734,3100823752),t(506948616,1363258195),t(659060556,3750685593),t(883997877,3785050280),t(958139571,3318307427),t(1322822218,3812723403),t(1537002063,2003034995),t(1747873779,3602036899),t(1955562222,1575990012),t(2024104815,1125592928),t(2227730452,2716904306),t(2361852424,442776044),t(2428436474,593698344),t(2756734187,3733110249),t(3204031479,2999351573),t(3329325298,3815920427),t(3391569614,3928383900),t(3515267271,566280711),t(3940187606,3454069534),t(4118630271,4000239992),t(116418474,1914138554),t(174292421,2731055270),t(289380356,3203993006),t(460393269,320620315),t(685471733,587496836),t(852142971,1086792851),t(1017036298,365543100),t(1126000580,2618297676),t(1288033470,3409855158),t(1501505948,4234509866),t(1607167915,987167468),t(1816402316,1246189591)],a=[],u=0;80>u;u++)a[u]=t();o=o.SHA512=r.extend({_doReset:function t(){this._hash=new i.init([new n.init(1779033703,4089235720),new n.init(3144134277,2227873595),new n.init(1013904242,4271175723),new n.init(2773480762,1595750129),new n.init(1359893119,2917565137),new n.init(2600822924,725511199),new n.init(528734635,4215389547),new n.init(1541459225,327033209)])},_doProcessBlock:function t(e,r){for(var n=(f=this._hash.words)[0],i=f[1],o=f[2],u=f[3],c=f[4],h=f[5],l=f[6],f=f[7],g=n.high,d=n.low,p=i.high,v=i.low,y=o.high,m=o.low,_=u.high,S=u.low,b=c.high,w=c.low,F=h.high,E=h.low,x=l.high,A=l.low,k=f.high,P=f.low,C=g,T=d,R=p,I=v,D=y,L=m,N=_,U=S,B=b,O=w,j=F,M=E,H=x,V=A,K=k,q=P,J=0;80>J;J++){var W=a[J];if(16>J)var z=W.high=0|e[r+2*J],Y=W.low=0|e[r+2*J+1];else{z=((Y=(z=a[J-15]).high)>>>1|(G=z.low)<<31)^(Y>>>8|G<<24)^Y>>>7;var G=(G>>>1|Y<<31)^(G>>>8|Y<<24)^(G>>>7|Y<<25),X=((Y=(X=a[J-2]).high)>>>19|($=X.low)<<13)^(Y<<3|$>>>29)^Y>>>6,$=($>>>19|Y<<13)^($<<3|Y>>>29)^($>>>6|Y<<26),Q=(Y=a[J-7]).high,Z=(tt=a[J-16]).high,tt=tt.low;z=(z=(z=z+Q+((Y=G+Y.low)>>>0<G>>>0?1:0))+X+((Y=Y+$)>>>0<$>>>0?1:0))+Z+((Y=Y+tt)>>>0<tt>>>0?1:0);W.high=z,W.low=Y}Q=B&j^~B&H,tt=O&M^~O&V,W=C&R^C&D^R&D;var et=T&I^T&L^I&L,rt=(G=(C>>>28|T<<4)^(C<<30|T>>>2)^(C<<25|T>>>7),X=(T>>>28|C<<4)^(T<<30|C>>>2)^(T<<25|C>>>7),($=s[J]).high),nt=$.low;Z=K+((B>>>14|O<<18)^(B>>>18|O<<14)^(B<<23|O>>>9))+(($=q+((O>>>14|B<<18)^(O>>>18|B<<14)^(O<<23|B>>>9)))>>>0<q>>>0?1:0),K=H,q=V,H=j,V=M,j=B,M=O,B=N+(Z=(Z=(Z=Z+Q+(($=$+tt)>>>0<tt>>>0?1:0))+rt+(($=$+nt)>>>0<nt>>>0?1:0))+z+(($=$+Y)>>>0<Y>>>0?1:0))+((O=U+$|0)>>>0<U>>>0?1:0)|0,N=D,U=L,D=R,L=I,R=C,I=T,C=Z+(W=G+W+((Y=X+et)>>>0<X>>>0?1:0))+((T=$+Y|0)>>>0<$>>>0?1:0)|0}d=n.low=d+T,n.high=g+C+(d>>>0<T>>>0?1:0),v=i.low=v+I,i.high=p+R+(v>>>0<I>>>0?1:0),m=o.low=m+L,o.high=y+D+(m>>>0<L>>>0?1:0),S=u.low=S+U,u.high=_+N+(S>>>0<U>>>0?1:0),w=c.low=w+O,c.high=b+B+(w>>>0<O>>>0?1:0),E=h.low=E+M,h.high=F+j+(E>>>0<M>>>0?1:0),A=l.low=A+V,l.high=x+H+(A>>>0<V>>>0?1:0),P=f.low=P+q,f.high=k+K+(P>>>0<q>>>0?1:0)},_doFinalize:function t(){var e=this._data,r=e.words,n=8*this._nDataBytes,i=8*e.sigBytes;return r[i>>>5]|=128<<24-i%32,r[30+(i+128>>>10<<5)]=Math.floor(n/4294967296),r[31+(i+128>>>10<<5)]=n,e.sigBytes=4*r.length,this._process(),this._hash.toX32()},clone:function t(){var e=r.clone.call(this);return e._hash=this._hash.clone(),e},blockSize:32}),e.SHA512=r._createHelper(o),e.HmacSHA512=r._createHmacHelper(o)}(),function(){var t=v,e=(i=t.x64).Word,r=i.WordArray,n=(i=t.algo).SHA512,i=i.SHA384=n.extend({_doReset:function t(){this._hash=new r.init([new e.init(3418070365,3238371032),new e.init(1654270250,914150663),new e.init(2438529370,812702999),new e.init(355462360,4144912697),new e.init(1731405415,4290775857),new e.init(2394180231,1750603025),new e.init(3675008525,1694076839),new e.init(1203062813,3204075428)])},_doFinalize:function t(){var e=n._doFinalize.call(this);return e.sigBytes-=16,e}});t.SHA384=n._createHelper(i),t.HmacSHA384=n._createHmacHelper(i)}();
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
var y,m="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";function _(t){var e,r,n="";for(e=0;e+3<=t.length;e+=3)r=parseInt(t.substring(e,e+3),16),n+=m.charAt(r>>6)+m.charAt(63&r);for(e+1==t.length?(r=parseInt(t.substring(e,e+1),16),n+=m.charAt(r<<2)):e+2==t.length&&(r=parseInt(t.substring(e,e+2),16),n+=m.charAt(r>>2)+m.charAt((3&r)<<4)),"=";(3&n.length)>0;)n+="=";return n}function S(t){var e,r,n,i="",o=0;for(e=0;e<t.length&&"="!=t.charAt(e);++e)(n=m.indexOf(t.charAt(e)))<0||(0==o?(i+=T(n>>2),r=3&n,o=1):1==o?(i+=T(r<<2|n>>4),r=15&n,o=2):2==o?(i+=T(r),i+=T(n>>2),r=3&n,o=3):(i+=T(r<<2|n>>4),i+=T(15&n),o=0));return 1==o&&(i+=T(r<<2)),i}function b(t){var e,r=S(t),n=new Array;for(e=0;2*e<r.length;++e)n[e]=parseInt(r.substring(2*e,2*e+2),16);return n}function w(t,e,r){null!=t&&("number"==typeof t?this.fromNumber(t,e,r):null==e&&"string"!=typeof t?this.fromString(t,256):this.fromString(t,e))}function F(){return new w(null)}"Microsoft Internet Explorer"==d.appName?(w.prototype.am=function E(t,e,r,n,i,o){for(var s=32767&e,a=e>>15;--o>=0;){var u=32767&this[t],c=this[t++]>>15,h=a*u+c*s;i=((u=s*u+((32767&h)<<15)+r[n]+(1073741823&i))>>>30)+(h>>>15)+a*c+(i>>>30),r[n++]=1073741823&u}return i},y=30):"Netscape"!=d.appName?(w.prototype.am=function x(t,e,r,n,i,o){for(;--o>=0;){var s=e*this[t++]+r[n]+i;i=Math.floor(s/67108864),r[n++]=67108863&s}return i},y=26):(w.prototype.am=function A(t,e,r,n,i,o){for(var s=16383&e,a=e>>14;--o>=0;){var u=16383&this[t],c=this[t++]>>14,h=a*u+c*s;i=((u=s*u+((16383&h)<<14)+r[n]+i)>>28)+(h>>14)+a*c,r[n++]=268435455&u}return i},y=28),w.prototype.DB=y,w.prototype.DM=(1<<y)-1,w.prototype.DV=1<<y;w.prototype.FV=Math.pow(2,52),w.prototype.F1=52-y,w.prototype.F2=2*y-52;var k,P,C=new Array;for(k="0".charCodeAt(0),P=0;P<=9;++P)C[k++]=P;for(k="a".charCodeAt(0),P=10;P<36;++P)C[k++]=P;for(k="A".charCodeAt(0),P=10;P<36;++P)C[k++]=P;function T(t){return"0123456789abcdefghijklmnopqrstuvwxyz".charAt(t)}function R(t,e){var r=C[t.charCodeAt(e)];return null==r?-1:r}function I(t){var e=F();return e.fromInt(t),e}function D(t){var e,r=1;return 0!=(e=t>>>16)&&(t=e,r+=16),0!=(e=t>>8)&&(t=e,r+=8),0!=(e=t>>4)&&(t=e,r+=4),0!=(e=t>>2)&&(t=e,r+=2),0!=(e=t>>1)&&(t=e,r+=1),r}function L(t){this.m=t}function N(t){this.m=t,this.mp=t.invDigit(),this.mpl=32767&this.mp,this.mph=this.mp>>15,this.um=(1<<t.DB-15)-1,this.mt2=2*t.t}function U(t,e){return t&e}function B(t,e){return t|e}function O(t,e){return t^e}function j(t,e){return t&~e}function M(t){if(0==t)return-1;var e=0;return 0==(65535&t)&&(t>>=16,e+=16),0==(255&t)&&(t>>=8,e+=8),0==(15&t)&&(t>>=4,e+=4),0==(3&t)&&(t>>=2,e+=2),0==(1&t)&&++e,e}function H(t){for(var e=0;0!=t;)t&=t-1,++e;return e}function V(){}function K(t){return t}function q(t){this.r2=F(),this.q3=F(),w.ONE.dlShiftTo(2*t.t,this.r2),this.mu=this.r2.divide(t),this.m=t}L.prototype.convert=function J(t){return t.s<0||t.compareTo(this.m)>=0?t.mod(this.m):t},L.prototype.revert=function W(t){return t},L.prototype.reduce=function z(t){t.divRemTo(this.m,null,t)},L.prototype.mulTo=function Y(t,e,r){t.multiplyTo(e,r),this.reduce(r)},L.prototype.sqrTo=function G(t,e){t.squareTo(e),this.reduce(e)},N.prototype.convert=function X(t){var e=F();return t.abs().dlShiftTo(this.m.t,e),e.divRemTo(this.m,null,e),t.s<0&&e.compareTo(w.ZERO)>0&&this.m.subTo(e,e),e},N.prototype.revert=function $(t){var e=F();return t.copyTo(e),this.reduce(e),e},N.prototype.reduce=function Q(t){for(;t.t<=this.mt2;)t[t.t++]=0;for(var e=0;e<this.m.t;++e){var r=32767&t[e],n=r*this.mpl+((r*this.mph+(t[e]>>15)*this.mpl&this.um)<<15)&t.DM;for(t[r=e+this.m.t]+=this.m.am(0,n,t,e,0,this.m.t);t[r]>=t.DV;)t[r]-=t.DV,t[++r]++}t.clamp(),t.drShiftTo(this.m.t,t),t.compareTo(this.m)>=0&&t.subTo(this.m,t)},N.prototype.mulTo=function Z(t,e,r){t.multiplyTo(e,r),this.reduce(r)},N.prototype.sqrTo=function tt(t,e){t.squareTo(e),this.reduce(e)},w.prototype.copyTo=function et(t){for(var e=this.t-1;e>=0;--e)t[e]=this[e];t.t=this.t,t.s=this.s},w.prototype.fromInt=function rt(t){this.t=1,this.s=t<0?-1:0,t>0?this[0]=t:t<-1?this[0]=t+this.DV:this.t=0},w.prototype.fromString=function nt(t,e){var r;if(16==e)r=4;else if(8==e)r=3;else if(256==e)r=8;else if(2==e)r=1;else if(32==e)r=5;else{if(4!=e)return void this.fromRadix(t,e);r=2}this.t=0,this.s=0;for(var n=t.length,i=!1,o=0;--n>=0;){var s=8==r?255&t[n]:R(t,n);s<0?"-"==t.charAt(n)&&(i=!0):(i=!1,0==o?this[this.t++]=s:o+r>this.DB?(this[this.t-1]|=(s&(1<<this.DB-o)-1)<<o,this[this.t++]=s>>this.DB-o):this[this.t-1]|=s<<o,(o+=r)>=this.DB&&(o-=this.DB))}8==r&&0!=(128&t[0])&&(this.s=-1,o>0&&(this[this.t-1]|=(1<<this.DB-o)-1<<o)),this.clamp(),i&&w.ZERO.subTo(this,this)},w.prototype.clamp=function it(){for(var t=this.s&this.DM;this.t>0&&this[this.t-1]==t;)--this.t},w.prototype.dlShiftTo=function ot(t,e){var r;for(r=this.t-1;r>=0;--r)e[r+t]=this[r];for(r=t-1;r>=0;--r)e[r]=0;e.t=this.t+t,e.s=this.s},w.prototype.drShiftTo=function st(t,e){for(var r=t;r<this.t;++r)e[r-t]=this[r];e.t=Math.max(this.t-t,0),e.s=this.s},w.prototype.lShiftTo=function at(t,e){var r,n=t%this.DB,i=this.DB-n,o=(1<<i)-1,s=Math.floor(t/this.DB),a=this.s<<n&this.DM;for(r=this.t-1;r>=0;--r)e[r+s+1]=this[r]>>i|a,a=(this[r]&o)<<n;for(r=s-1;r>=0;--r)e[r]=0;e[s]=a,e.t=this.t+s+1,e.s=this.s,e.clamp()},w.prototype.rShiftTo=function ut(t,e){e.s=this.s;var r=Math.floor(t/this.DB);if(r>=this.t)e.t=0;else{var n=t%this.DB,i=this.DB-n,o=(1<<n)-1;e[0]=this[r]>>n;for(var s=r+1;s<this.t;++s)e[s-r-1]|=(this[s]&o)<<i,e[s-r]=this[s]>>n;n>0&&(e[this.t-r-1]|=(this.s&o)<<i),e.t=this.t-r,e.clamp()}},w.prototype.subTo=function ct(t,e){for(var r=0,n=0,i=Math.min(t.t,this.t);r<i;)n+=this[r]-t[r],e[r++]=n&this.DM,n>>=this.DB;if(t.t<this.t){for(n-=t.s;r<this.t;)n+=this[r],e[r++]=n&this.DM,n>>=this.DB;n+=this.s}else{for(n+=this.s;r<t.t;)n-=t[r],e[r++]=n&this.DM,n>>=this.DB;n-=t.s}e.s=n<0?-1:0,n<-1?e[r++]=this.DV+n:n>0&&(e[r++]=n),e.t=r,e.clamp()},w.prototype.multiplyTo=function ht(t,e){var r=this.abs(),n=t.abs(),i=r.t;for(e.t=i+n.t;--i>=0;)e[i]=0;for(i=0;i<n.t;++i)e[i+r.t]=r.am(0,n[i],e,i,0,r.t);e.s=0,e.clamp(),this.s!=t.s&&w.ZERO.subTo(e,e)},w.prototype.squareTo=function lt(t){for(var e=this.abs(),r=t.t=2*e.t;--r>=0;)t[r]=0;for(r=0;r<e.t-1;++r){var n=e.am(r,e[r],t,2*r,0,1);(t[r+e.t]+=e.am(r+1,2*e[r],t,2*r+1,n,e.t-r-1))>=e.DV&&(t[r+e.t]-=e.DV,t[r+e.t+1]=1)}t.t>0&&(t[t.t-1]+=e.am(r,e[r],t,2*r,0,1)),t.s=0,t.clamp()},w.prototype.divRemTo=function ft(t,e,r){var n=t.abs();if(!(n.t<=0)){var i=this.abs();if(i.t<n.t)return null!=e&&e.fromInt(0),void(null!=r&&this.copyTo(r));null==r&&(r=F());var o=F(),s=this.s,a=t.s,u=this.DB-D(n[n.t-1]);u>0?(n.lShiftTo(u,o),i.lShiftTo(u,r)):(n.copyTo(o),i.copyTo(r));var c=o.t,h=o[c-1];if(0!=h){var l=h*(1<<this.F1)+(c>1?o[c-2]>>this.F2:0),f=this.FV/l,g=(1<<this.F1)/l,d=1<<this.F2,p=r.t,v=p-c,y=null==e?F():e;for(o.dlShiftTo(v,y),r.compareTo(y)>=0&&(r[r.t++]=1,r.subTo(y,r)),w.ONE.dlShiftTo(c,y),y.subTo(o,o);o.t<c;)o[o.t++]=0;for(;--v>=0;){var m=r[--p]==h?this.DM:Math.floor(r[p]*f+(r[p-1]+d)*g);if((r[p]+=o.am(0,m,r,v,0,c))<m)for(o.dlShiftTo(v,y),r.subTo(y,r);r[p]<--m;)r.subTo(y,r)}null!=e&&(r.drShiftTo(c,e),s!=a&&w.ZERO.subTo(e,e)),r.t=c,r.clamp(),u>0&&r.rShiftTo(u,r),s<0&&w.ZERO.subTo(r,r)}}},w.prototype.invDigit=function gt(){if(this.t<1)return 0;var t=this[0];if(0==(1&t))return 0;var e=3&t;return(e=(e=(e=(e=e*(2-(15&t)*e)&15)*(2-(255&t)*e)&255)*(2-((65535&t)*e&65535))&65535)*(2-t*e%this.DV)%this.DV)>0?this.DV-e:-e},w.prototype.isEven=function dt(){return 0==(this.t>0?1&this[0]:this.s)},w.prototype.exp=function pt(t,e){if(t>4294967295||t<1)return w.ONE;var r=F(),n=F(),i=e.convert(this),o=D(t)-1;for(i.copyTo(r);--o>=0;)if(e.sqrTo(r,n),(t&1<<o)>0)e.mulTo(n,i,r);else{var s=r;r=n,n=s}return e.revert(r)},w.prototype.toString=function vt(t){if(this.s<0)return"-"+this.negate().toString(t);var e;if(16==t)e=4;else if(8==t)e=3;else if(2==t)e=1;else if(32==t)e=5;else{if(4!=t)return this.toRadix(t);e=2}var r,n=(1<<e)-1,i=!1,o="",s=this.t,a=this.DB-s*this.DB%e;if(s-- >0)for(a<this.DB&&(r=this[s]>>a)>0&&(i=!0,o=T(r));s>=0;)a<e?(r=(this[s]&(1<<a)-1)<<e-a,r|=this[--s]>>(a+=this.DB-e)):(r=this[s]>>(a-=e)&n,a<=0&&(a+=this.DB,--s)),r>0&&(i=!0),i&&(o+=T(r));return i?o:"0"},w.prototype.negate=function yt(){var t=F();return w.ZERO.subTo(this,t),t},w.prototype.abs=function mt(){return this.s<0?this.negate():this},w.prototype.compareTo=function _t(t){var e=this.s-t.s;if(0!=e)return e;var r=this.t;if(0!=(e=r-t.t))return this.s<0?-e:e;for(;--r>=0;)if(0!=(e=this[r]-t[r]))return e;return 0},w.prototype.bitLength=function St(){return this.t<=0?0:this.DB*(this.t-1)+D(this[this.t-1]^this.s&this.DM)},w.prototype.mod=function bt(t){var e=F();return this.abs().divRemTo(t,null,e),this.s<0&&e.compareTo(w.ZERO)>0&&t.subTo(e,e),e},w.prototype.modPowInt=function wt(t,e){var r;return r=t<256||e.isEven()?new L(e):new N(e),this.exp(t,r)},w.ZERO=I(0),w.ONE=I(1),V.prototype.convert=K,V.prototype.revert=K,V.prototype.mulTo=function Ft(t,e,r){t.multiplyTo(e,r)},V.prototype.sqrTo=function Et(t,e){t.squareTo(e)},q.prototype.convert=function xt(t){if(t.s<0||t.t>2*this.m.t)return t.mod(this.m);if(t.compareTo(this.m)<0)return t;var e=F();return t.copyTo(e),this.reduce(e),e},q.prototype.revert=function At(t){return t},q.prototype.reduce=function kt(t){for(t.drShiftTo(this.m.t-1,this.r2),t.t>this.m.t+1&&(t.t=this.m.t+1,t.clamp()),this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3),this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);t.compareTo(this.r2)<0;)t.dAddOffset(1,this.m.t+1);for(t.subTo(this.r2,t);t.compareTo(this.m)>=0;)t.subTo(this.m,t)},q.prototype.mulTo=function Pt(t,e,r){t.multiplyTo(e,r),this.reduce(r)},q.prototype.sqrTo=function Ct(t,e){t.squareTo(e),this.reduce(e)};var Tt=[2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997],Rt=(1<<26)/Tt[Tt.length-1];
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
function It(){this.i=0,this.j=0,this.S=new Array}w.prototype.chunkSize=function Dt(t){return Math.floor(Math.LN2*this.DB/Math.log(t))},w.prototype.toRadix=function Lt(t){if(null==t&&(t=10),0==this.signum()||t<2||t>36)return"0";var e=this.chunkSize(t),r=Math.pow(t,e),n=I(r),i=F(),o=F(),s="";for(this.divRemTo(n,i,o);i.signum()>0;)s=(r+o.intValue()).toString(t).substr(1)+s,i.divRemTo(n,i,o);return o.intValue().toString(t)+s},w.prototype.fromRadix=function Nt(t,e){this.fromInt(0),null==e&&(e=10);for(var r=this.chunkSize(e),n=Math.pow(e,r),i=!1,o=0,s=0,a=0;a<t.length;++a){var u=R(t,a);u<0?"-"==t.charAt(a)&&0==this.signum()&&(i=!0):(s=e*s+u,++o>=r&&(this.dMultiply(n),this.dAddOffset(s,0),o=0,s=0))}o>0&&(this.dMultiply(Math.pow(e,o)),this.dAddOffset(s,0)),i&&w.ZERO.subTo(this,this)},w.prototype.fromNumber=function Ut(t,e,r){if("number"==typeof e)if(t<2)this.fromInt(1);else for(this.fromNumber(t,r),this.testBit(t-1)||this.bitwiseTo(w.ONE.shiftLeft(t-1),B,this),this.isEven()&&this.dAddOffset(1,0);!this.isProbablePrime(e);)this.dAddOffset(2,0),this.bitLength()>t&&this.subTo(w.ONE.shiftLeft(t-1),this);else{var n=new Array,i=7&t;n.length=1+(t>>3),e.nextBytes(n),i>0?n[0]&=(1<<i)-1:n[0]=0,this.fromString(n,256)}},w.prototype.bitwiseTo=function Bt(t,e,r){var n,i,o=Math.min(t.t,this.t);for(n=0;n<o;++n)r[n]=e(this[n],t[n]);if(t.t<this.t){for(i=t.s&this.DM,n=o;n<this.t;++n)r[n]=e(this[n],i);r.t=this.t}else{for(i=this.s&this.DM,n=o;n<t.t;++n)r[n]=e(i,t[n]);r.t=t.t}r.s=e(this.s,t.s),r.clamp()},w.prototype.changeBit=function Ot(t,e){var r=w.ONE.shiftLeft(t);return this.bitwiseTo(r,e,r),r},w.prototype.addTo=function jt(t,e){for(var r=0,n=0,i=Math.min(t.t,this.t);r<i;)n+=this[r]+t[r],e[r++]=n&this.DM,n>>=this.DB;if(t.t<this.t){for(n+=t.s;r<this.t;)n+=this[r],e[r++]=n&this.DM,n>>=this.DB;n+=this.s}else{for(n+=this.s;r<t.t;)n+=t[r],e[r++]=n&this.DM,n>>=this.DB;n+=t.s}e.s=n<0?-1:0,n>0?e[r++]=n:n<-1&&(e[r++]=this.DV+n),e.t=r,e.clamp()},w.prototype.dMultiply=function Mt(t){this[this.t]=this.am(0,t-1,this,0,0,this.t),++this.t,this.clamp()},w.prototype.dAddOffset=function Ht(t,e){if(0!=t){for(;this.t<=e;)this[this.t++]=0;for(this[e]+=t;this[e]>=this.DV;)this[e]-=this.DV,++e>=this.t&&(this[this.t++]=0),++this[e]}},w.prototype.multiplyLowerTo=function Vt(t,e,r){var n,i=Math.min(this.t+t.t,e);for(r.s=0,r.t=i;i>0;)r[--i]=0;for(n=r.t-this.t;i<n;++i)r[i+this.t]=this.am(0,t[i],r,i,0,this.t);for(n=Math.min(t.t,e);i<n;++i)this.am(0,t[i],r,i,0,e-i);r.clamp()},w.prototype.multiplyUpperTo=function Kt(t,e,r){--e;var n=r.t=this.t+t.t-e;for(r.s=0;--n>=0;)r[n]=0;for(n=Math.max(e-this.t,0);n<t.t;++n)r[this.t+n-e]=this.am(e-n,t[n],r,0,0,this.t+n-e);r.clamp(),r.drShiftTo(1,r)},w.prototype.modInt=function qt(t){if(t<=0)return 0;var e=this.DV%t,r=this.s<0?t-1:0;if(this.t>0)if(0==e)r=this[0]%t;else for(var n=this.t-1;n>=0;--n)r=(e*r+this[n])%t;return r},w.prototype.millerRabin=function Jt(t){var e=this.subtract(w.ONE),r=e.getLowestSetBit();if(r<=0)return!1;var n=e.shiftRight(r);(t=t+1>>1)>Tt.length&&(t=Tt.length);for(var i=F(),o=0;o<t;++o){i.fromInt(Tt[Math.floor(Math.random()*Tt.length)]);var s=i.modPow(n,this);if(0!=s.compareTo(w.ONE)&&0!=s.compareTo(e)){for(var a=1;a++<r&&0!=s.compareTo(e);)if(0==(s=s.modPowInt(2,this)).compareTo(w.ONE))return!1;if(0!=s.compareTo(e))return!1}}return!0},w.prototype.clone=
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
function Wt(){var t=F();return this.copyTo(t),t},w.prototype.intValue=function zt(){if(this.s<0){if(1==this.t)return this[0]-this.DV;if(0==this.t)return-1}else{if(1==this.t)return this[0];if(0==this.t)return 0}return(this[1]&(1<<32-this.DB)-1)<<this.DB|this[0]},w.prototype.byteValue=function Yt(){return 0==this.t?this.s:this[0]<<24>>24},w.prototype.shortValue=function Gt(){return 0==this.t?this.s:this[0]<<16>>16},w.prototype.signum=function Xt(){return this.s<0?-1:this.t<=0||1==this.t&&this[0]<=0?0:1},w.prototype.toByteArray=function $t(){var t=this.t,e=new Array;e[0]=this.s;var r,n=this.DB-t*this.DB%8,i=0;if(t-- >0)for(n<this.DB&&(r=this[t]>>n)!=(this.s&this.DM)>>n&&(e[i++]=r|this.s<<this.DB-n);t>=0;)n<8?(r=(this[t]&(1<<n)-1)<<8-n,r|=this[--t]>>(n+=this.DB-8)):(r=this[t]>>(n-=8)&255,n<=0&&(n+=this.DB,--t)),0!=(128&r)&&(r|=-256),0==i&&(128&this.s)!=(128&r)&&++i,(i>0||r!=this.s)&&(e[i++]=r);return e},w.prototype.equals=function Qt(t){return 0==this.compareTo(t)},w.prototype.min=function Zt(t){return this.compareTo(t)<0?this:t},w.prototype.max=function te(t){return this.compareTo(t)>0?this:t},w.prototype.and=function ee(t){var e=F();return this.bitwiseTo(t,U,e),e},w.prototype.or=function re(t){var e=F();return this.bitwiseTo(t,B,e),e},w.prototype.xor=function ne(t){var e=F();return this.bitwiseTo(t,O,e),e},w.prototype.andNot=function ie(t){var e=F();return this.bitwiseTo(t,j,e),e},w.prototype.not=function oe(){for(var t=F(),e=0;e<this.t;++e)t[e]=this.DM&~this[e];return t.t=this.t,t.s=~this.s,t},w.prototype.shiftLeft=function se(t){var e=F();return t<0?this.rShiftTo(-t,e):this.lShiftTo(t,e),e},w.prototype.shiftRight=function ae(t){var e=F();return t<0?this.lShiftTo(-t,e):this.rShiftTo(t,e),e},w.prototype.getLowestSetBit=function ue(){for(var t=0;t<this.t;++t)if(0!=this[t])return t*this.DB+M(this[t]);return this.s<0?this.t*this.DB:-1},w.prototype.bitCount=function ce(){for(var t=0,e=this.s&this.DM,r=0;r<this.t;++r)t+=H(this[r]^e);return t},w.prototype.testBit=function he(t){var e=Math.floor(t/this.DB);return e>=this.t?0!=this.s:0!=(this[e]&1<<t%this.DB)},w.prototype.setBit=function le(t){return this.changeBit(t,B)},w.prototype.clearBit=function fe(t){return this.changeBit(t,j)},w.prototype.flipBit=function ge(t){return this.changeBit(t,O)},w.prototype.add=function de(t){var e=F();return this.addTo(t,e),e},w.prototype.subtract=function pe(t){var e=F();return this.subTo(t,e),e},w.prototype.multiply=function ve(t){var e=F();return this.multiplyTo(t,e),e},w.prototype.divide=function ye(t){var e=F();return this.divRemTo(t,e,null),e},w.prototype.remainder=function me(t){var e=F();return this.divRemTo(t,null,e),e},w.prototype.divideAndRemainder=function _e(t){var e=F(),r=F();return this.divRemTo(t,e,r),new Array(e,r)},w.prototype.modPow=function Se(t,e){var r,n,i=t.bitLength(),o=I(1);if(i<=0)return o;r=i<18?1:i<48?3:i<144?4:i<768?5:6,n=i<8?new L(e):e.isEven()?new q(e):new N(e);var s=new Array,a=3,u=r-1,c=(1<<r)-1;if(s[1]=n.convert(this),r>1){var h=F();for(n.sqrTo(s[1],h);a<=c;)s[a]=F(),n.mulTo(h,s[a-2],s[a]),a+=2}var l,f,g=t.t-1,d=!0,p=F();for(i=D(t[g])-1;g>=0;){for(i>=u?l=t[g]>>i-u&c:(l=(t[g]&(1<<i+1)-1)<<u-i,g>0&&(l|=t[g-1]>>this.DB+i-u)),a=r;0==(1&l);)l>>=1,--a;if((i-=a)<0&&(i+=this.DB,--g),d)s[l].copyTo(o),d=!1;else{for(;a>1;)n.sqrTo(o,p),n.sqrTo(p,o),a-=2;a>0?n.sqrTo(o,p):(f=o,o=p,p=f),n.mulTo(p,s[l],o)}for(;g>=0&&0==(t[g]&1<<i);)n.sqrTo(o,p),f=o,o=p,p=f,--i<0&&(i=this.DB-1,--g)}return n.revert(o)},w.prototype.modInverse=function be(t){var e=t.isEven();if(this.isEven()&&e||0==t.signum())return w.ZERO;for(var r=t.clone(),n=this.clone(),i=I(1),o=I(0),s=I(0),a=I(1);0!=r.signum();){for(;r.isEven();)r.rShiftTo(1,r),e?(i.isEven()&&o.isEven()||(i.addTo(this,i),o.subTo(t,o)),i.rShiftTo(1,i)):o.isEven()||o.subTo(t,o),o.rShiftTo(1,o);for(;n.isEven();)n.rShiftTo(1,n),e?(s.isEven()&&a.isEven()||(s.addTo(this,s),a.subTo(t,a)),s.rShiftTo(1,s)):a.isEven()||a.subTo(t,a),a.rShiftTo(1,a);r.compareTo(n)>=0?(r.subTo(n,r),e&&i.subTo(s,i),o.subTo(a,o)):(n.subTo(r,n),e&&s.subTo(i,s),a.subTo(o,a))}return 0!=n.compareTo(w.ONE)?w.ZERO:a.compareTo(t)>=0?a.subtract(t):a.signum()<0?(a.addTo(t,a),a.signum()<0?a.add(t):a):a},w.prototype.pow=function we(t){return this.exp(t,new V)},w.prototype.gcd=function Fe(t){var e=this.s<0?this.negate():this.clone(),r=t.s<0?t.negate():t.clone();if(e.compareTo(r)<0){var n=e;e=r,r=n}var i=e.getLowestSetBit(),o=r.getLowestSetBit();if(o<0)return e;for(i<o&&(o=i),o>0&&(e.rShiftTo(o,e),r.rShiftTo(o,r));e.signum()>0;)(i=e.getLowestSetBit())>0&&e.rShiftTo(i,e),(i=r.getLowestSetBit())>0&&r.rShiftTo(i,r),e.compareTo(r)>=0?(e.subTo(r,e),e.rShiftTo(1,e)):(r.subTo(e,r),r.rShiftTo(1,r));return o>0&&r.lShiftTo(o,r),r},w.prototype.isProbablePrime=function Ee(t){var e,r=this.abs();if(1==r.t&&r[0]<=Tt[Tt.length-1]){for(e=0;e<Tt.length;++e)if(r[0]==Tt[e])return!0;return!1}if(r.isEven())return!1;for(e=1;e<Tt.length;){for(var n=Tt[e],i=e+1;i<Tt.length&&n<Rt;)n*=Tt[i++];for(n=r.modInt(n);e<i;)if(n%Tt[e++]==0)return!1}return r.millerRabin(t)},w.prototype.square=function xe(){var t=F();return this.squareTo(t),t},It.prototype.init=function Ae(t){var e,r,n;for(e=0;e<256;++e)this.S[e]=e;for(r=0,e=0;e<256;++e)r=r+this.S[e]+t[e%t.length]&255,n=this.S[e],this.S[e]=this.S[r],this.S[r]=n;this.i=0,this.j=0},It.prototype.next=function ke(){var t;return this.i=this.i+1&255,this.j=this.j+this.S[this.i]&255,t=this.S[this.i],this.S[this.i]=this.S[this.j],this.S[this.j]=t,this.S[t+this.S[this.i]&255]};var Pe,Ce,Te;
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */function Re(){!function t(e){Ce[Te++]^=255&e,Ce[Te++]^=e>>8&255,Ce[Te++]^=e>>16&255,Ce[Te++]^=e>>24&255,Te>=256&&(Te-=256)}((new Date).getTime())}if(null==Ce){var Ie;if(Ce=new Array,Te=0,void 0!==p&&(void 0!==p.crypto||void 0!==p.msCrypto)){var De=p.crypto||p.msCrypto;if(De.getRandomValues){var Le=new Uint8Array(32);for(De.getRandomValues(Le),Ie=0;Ie<32;++Ie)Ce[Te++]=Le[Ie]}else if("Netscape"==d.appName&&d.appVersion<"5"){var Ne=p.crypto.random(32);for(Ie=0;Ie<Ne.length;++Ie)Ce[Te++]=255&Ne.charCodeAt(Ie)}}for(;Te<256;)Ie=Math.floor(65536*Math.random()),Ce[Te++]=Ie>>>8,Ce[Te++]=255&Ie;Te=0,Re()}function Ue(){if(null==Pe){for(Re(),(Pe=function t(){return new It}()).init(Ce),Te=0;Te<Ce.length;++Te)Ce[Te]=0;Te=0}return Pe.next()}function Be(){}
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
function Oe(t,e){return new w(t,e)}function je(t,e,r){for(var n="",i=0;n.length<e;)n+=r(String.fromCharCode.apply(String,t.concat([(4278190080&i)>>24,(16711680&i)>>16,(65280&i)>>8,255&i]))),i+=1;return n}function Me(){this.n=null,this.e=0,this.d=null,this.p=null,this.q=null,this.dmp1=null,this.dmq1=null,this.coeff=null}
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
function He(t,e){this.x=e,this.q=t}function Ve(t,e,r,n){this.curve=t,this.x=e,this.y=r,this.z=null==n?w.ONE:n,this.zinv=null}function Ke(t,e,r){this.q=t,this.a=this.fromBigInteger(e),this.b=this.fromBigInteger(r),this.infinity=new Ve(this,null,null)}Be.prototype.nextBytes=function qe(t){var e;for(e=0;e<t.length;++e)t[e]=Ue()},Me.prototype.doPublic=function Je(t){return t.modPowInt(this.e,this.n)},Me.prototype.setPublic=function We(t,e){if(this.isPublic=!0,this.isPrivate=!1,"string"!=typeof t)this.n=t,this.e=e;else{if(!(null!=t&&null!=e&&t.length>0&&e.length>0))throw"Invalid RSA public key";this.n=Oe(t,16),this.e=parseInt(e,16)}},Me.prototype.encrypt=function ze(t){var e=function r(t,e){if(e<t.length+11)throw"Message too long for RSA";for(var r=new Array,n=t.length-1;n>=0&&e>0;){var i=t.charCodeAt(n--);i<128?r[--e]=i:i>127&&i<2048?(r[--e]=63&i|128,r[--e]=i>>6|192):(r[--e]=63&i|128,r[--e]=i>>6&63|128,r[--e]=i>>12|224)}r[--e]=0;for(var o=new Be,s=new Array;e>2;){for(s[0]=0;0==s[0];)o.nextBytes(s);r[--e]=s[0]}return r[--e]=2,r[--e]=0,new w(r)}(t,this.n.bitLength()+7>>3);if(null==e)return null;var n=this.doPublic(e);if(null==n)return null;var i=n.toString(16);return 0==(1&i.length)?i:"0"+i},Me.prototype.encryptOAEP=function Ye(t,e,r){var n=function i(t,e,r,n){var i=Sr.crypto.MessageDigest,o=Sr.crypto.Util,s=null;if(r||(r="sha1"),"string"==typeof r&&(s=i.getCanonicalAlgName(r),n=i.getHashLength(s),r=function t(e){return Lr(o.hashHex(Nr(e),s))}),t.length+2*n+2>e)throw"Message too long for RSA";var a,u="";for(a=0;a<e-t.length-2*n-2;a+=1)u+="\0";var c=r("")+u+""+t,h=new Array(n);(new Be).nextBytes(h);var l=je(h,c.length,r),f=[];for(a=0;a<c.length;a+=1)f[a]=c.charCodeAt(a)^l.charCodeAt(a);var g=je(f,h.length,r),d=[0];for(a=0;a<h.length;a+=1)d[a+1]=h[a]^g.charCodeAt(a);return new w(d.concat(f))}(t,this.n.bitLength()+7>>3,e,r);if(null==n)return null;var o=this.doPublic(n);if(null==o)return null;var s=o.toString(16);return 0==(1&s.length)?s:"0"+s},Me.prototype.type="RSA",He.prototype.equals=function Ge(t){return t==this||this.q.equals(t.q)&&this.x.equals(t.x)},He.prototype.toBigInteger=function Xe(){return this.x},He.prototype.negate=function $e(){return new He(this.q,this.x.negate().mod(this.q))},He.prototype.add=function Qe(t){return new He(this.q,this.x.add(t.toBigInteger()).mod(this.q))},He.prototype.subtract=function Ze(t){return new He(this.q,this.x.subtract(t.toBigInteger()).mod(this.q))},He.prototype.multiply=function tr(t){return new He(this.q,this.x.multiply(t.toBigInteger()).mod(this.q))},He.prototype.square=function er(){return new He(this.q,this.x.square().mod(this.q))},He.prototype.divide=function rr(t){return new He(this.q,this.x.multiply(t.toBigInteger().modInverse(this.q)).mod(this.q))},Ve.prototype.getX=function nr(){return null==this.zinv&&(this.zinv=this.z.modInverse(this.curve.q)),this.curve.fromBigInteger(this.x.toBigInteger().multiply(this.zinv).mod(this.curve.q))},Ve.prototype.getY=function ir(){return null==this.zinv&&(this.zinv=this.z.modInverse(this.curve.q)),this.curve.fromBigInteger(this.y.toBigInteger().multiply(this.zinv).mod(this.curve.q))},Ve.prototype.equals=function or(t){return t==this||(this.isInfinity()?t.isInfinity():t.isInfinity()?this.isInfinity():!!t.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(t.z)).mod(this.curve.q).equals(w.ZERO)&&t.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(t.z)).mod(this.curve.q).equals(w.ZERO))},Ve.prototype.isInfinity=function sr(){return null==this.x&&null==this.y||this.z.equals(w.ZERO)&&!this.y.toBigInteger().equals(w.ZERO)},Ve.prototype.negate=function ar(){return new Ve(this.curve,this.x,this.y.negate(),this.z)},Ve.prototype.add=function ur(t){if(this.isInfinity())return t;if(t.isInfinity())return this;var e=t.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(t.z)).mod(this.curve.q),r=t.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(t.z)).mod(this.curve.q);if(w.ZERO.equals(r))return w.ZERO.equals(e)?this.twice():this.curve.getInfinity();var n=new w("3"),i=this.x.toBigInteger(),o=this.y.toBigInteger(),s=(t.x.toBigInteger(),t.y.toBigInteger(),r.square()),a=s.multiply(r),u=i.multiply(s),c=e.square().multiply(this.z),h=c.subtract(u.shiftLeft(1)).multiply(t.z).subtract(a).multiply(r).mod(this.curve.q),l=u.multiply(n).multiply(e).subtract(o.multiply(a)).subtract(c.multiply(e)).multiply(t.z).add(e.multiply(a)).mod(this.curve.q),f=a.multiply(this.z).multiply(t.z).mod(this.curve.q);return new Ve(this.curve,this.curve.fromBigInteger(h),this.curve.fromBigInteger(l),f)},Ve.prototype.twice=function cr(){if(this.isInfinity())return this;if(0==this.y.toBigInteger().signum())return this.curve.getInfinity();var t=new w("3"),e=this.x.toBigInteger(),r=this.y.toBigInteger(),n=r.multiply(this.z),i=n.multiply(r).mod(this.curve.q),o=this.curve.a.toBigInteger(),s=e.square().multiply(t);w.ZERO.equals(o)||(s=s.add(this.z.square().multiply(o)));var a=(s=s.mod(this.curve.q)).square().subtract(e.shiftLeft(3).multiply(i)).shiftLeft(1).multiply(n).mod(this.curve.q),u=s.multiply(t).multiply(e).subtract(i.shiftLeft(1)).shiftLeft(2).multiply(i).subtract(s.square().multiply(s)).mod(this.curve.q),c=n.square().multiply(n).shiftLeft(3).mod(this.curve.q);return new Ve(this.curve,this.curve.fromBigInteger(a),this.curve.fromBigInteger(u),c)},Ve.prototype.multiply=function hr(t){if(this.isInfinity())return this;if(0==t.signum())return this.curve.getInfinity();var e,r=t,n=r.multiply(new w("3")),i=this.negate(),o=this,s=this.curve.q.subtract(t),a=s.multiply(new w("3")),u=new Ve(this.curve,this.x,this.y),c=u.negate();for(e=n.bitLength()-2;e>0;--e){o=o.twice();var h=n.testBit(e);h!=r.testBit(e)&&(o=o.add(h?this:i))}for(e=a.bitLength()-2;e>0;--e){u=u.twice();var l=a.testBit(e);l!=s.testBit(e)&&(u=u.add(l?u:c))}return o},Ve.prototype.multiplyTwo=function lr(t,e,r){var n;n=t.bitLength()>r.bitLength()?t.bitLength()-1:r.bitLength()-1;for(var i=this.curve.getInfinity(),o=this.add(e);n>=0;)i=i.twice(),t.testBit(n)?i=r.testBit(n)?i.add(o):i.add(this):r.testBit(n)&&(i=i.add(e)),--n;return i},Ke.prototype.getQ=function fr(){return this.q},Ke.prototype.getA=function gr(){return this.a},Ke.prototype.getB=function dr(){return this.b},Ke.prototype.equals=function pr(t){return t==this||this.q.equals(t.q)&&this.a.equals(t.a)&&this.b.equals(t.b)},Ke.prototype.getInfinity=function vr(){return this.infinity},Ke.prototype.fromBigInteger=function yr(t){return new He(this.q,t)},Ke.prototype.decodePointHex=function mr(t){switch(parseInt(t.substr(0,2),16)){case 0:return this.infinity;case 2:case 3:return null;case 4:case 6:case 7:var e=(t.length-2)/2,r=t.substr(2,e),n=t.substr(e+2,e);return new Ve(this,this.fromBigInteger(new w(r,16)),this.fromBigInteger(new w(n,16)));default:return null}},
/*! (c) Stefan Thomas | https://github.com/bitcoinjs/bitcoinjs-lib
 */
He.prototype.getByteLength=function(){return Math.floor((this.toBigInteger().bitLength()+7)/8)},Ve.prototype.getEncoded=function(t){var e=function t(e,r){var n=e.toByteArrayUnsigned();if(r<n.length)n=n.slice(n.length-r);else for(;r>n.length;)n.unshift(0);return n},r=this.getX().toBigInteger(),n=this.getY().toBigInteger(),i=e(r,32);return t?n.isEven()?i.unshift(2):i.unshift(3):(i.unshift(4),i=i.concat(e(n,32))),i},Ve.decodeFrom=function(t,e){e[0];var r=e.length-1,n=e.slice(1,1+r/2),i=e.slice(1+r/2,1+r);n.unshift(0),i.unshift(0);var o=new w(n),s=new w(i);return new Ve(t,t.fromBigInteger(o),t.fromBigInteger(s))},Ve.decodeFromHex=function(t,e){e.substr(0,2);var r=e.length-2,n=e.substr(2,r/2),i=e.substr(2+r/2,r/2),o=new w(n,16),s=new w(i,16);return new Ve(t,t.fromBigInteger(o),t.fromBigInteger(s))},Ve.prototype.add2D=function(t){if(this.isInfinity())return t;if(t.isInfinity())return this;if(this.x.equals(t.x))return this.y.equals(t.y)?this.twice():this.curve.getInfinity();var e=t.x.subtract(this.x),r=t.y.subtract(this.y).divide(e),n=r.square().subtract(this.x).subtract(t.x),i=r.multiply(this.x.subtract(n)).subtract(this.y);return new Ve(this.curve,n,i)},Ve.prototype.twice2D=function(){if(this.isInfinity())return this;if(0==this.y.toBigInteger().signum())return this.curve.getInfinity();var t=this.curve.fromBigInteger(w.valueOf(2)),e=this.curve.fromBigInteger(w.valueOf(3)),r=this.x.square().multiply(e).add(this.curve.a).divide(this.y.multiply(t)),n=r.square().subtract(this.x.multiply(t)),i=r.multiply(this.x.subtract(n)).subtract(this.y);return new Ve(this.curve,n,i)},Ve.prototype.multiply2D=function(t){if(this.isInfinity())return this;if(0==t.signum())return this.curve.getInfinity();var e,r=t,n=r.multiply(new w("3")),i=this.negate(),o=this;for(e=n.bitLength()-2;e>0;--e){o=o.twice();var s=n.testBit(e);s!=r.testBit(e)&&(o=o.add2D(s?this:i))}return o},Ve.prototype.isOnCurve=function(){var t=this.getX().toBigInteger(),e=this.getY().toBigInteger(),r=this.curve.getA().toBigInteger(),n=this.curve.getB().toBigInteger(),i=this.curve.getQ(),o=e.multiply(e).mod(i),s=t.multiply(t).multiply(t).add(r.multiply(t)).add(n).mod(i);return o.equals(s)},Ve.prototype.toString=function(){return"("+this.getX().toBigInteger().toString()+","+this.getY().toBigInteger().toString()+")"},Ve.prototype.validate=function(){var t=this.curve.getQ();if(this.isInfinity())throw new Error("Point is at infinity.");var e=this.getX().toBigInteger(),r=this.getY().toBigInteger();if(e.compareTo(w.ONE)<0||e.compareTo(t.subtract(w.ONE))>0)throw new Error("x coordinate out of bounds");if(r.compareTo(w.ONE)<0||r.compareTo(t.subtract(w.ONE))>0)throw new Error("y coordinate out of bounds");if(!this.isOnCurve())throw new Error("Point is not on the curve.");if(this.multiply(t).isInfinity())throw new Error("Point is not a scalar multiple of G.");return!0};
/*! Mike Samuel (c) 2009 | code.google.com/p/json-sans-eval
 */
var _r=function(){var t=new RegExp('(?:false|true|null|[\\{\\}\\[\\]]|(?:-?\\b(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\\b)|(?:"(?:[^\\0-\\x08\\x0a-\\x1f"\\\\]|\\\\(?:["/\\\\bfnrt]|u[0-9A-Fa-f]{4}))*"))',"g"),e=new RegExp("\\\\(?:([^u])|u(.{4}))","g"),r={'"':'"',"/":"/","\\":"\\",b:"\b",f:"\f",n:"\n",r:"\r",t:"\t"};function n(t,e,n){return e?r[e]:String.fromCharCode(parseInt(n,16))}var i=new String(""),o=Object.hasOwnProperty;return function(r,s){var a,u,c=r.match(t),h=c[0],l=!1;"{"===h?a={}:"["===h?a=[]:(a=[],l=!0);for(var f=[a],d=1-l,p=c.length;d<p;++d){var v;switch((h=c[d]).charCodeAt(0)){default:(v=f[0])[u||v.length]=+h,u=void 0;break;case 34:if(-1!==(h=h.substring(1,h.length-1)).indexOf("\\")&&(h=h.replace(e,n)),v=f[0],!u){if(!(v instanceof Array)){u=h||i;break}u=v.length}v[u]=h,u=void 0;break;case 91:v=f[0],f.unshift(v[u||v.length]=[]),u=void 0;break;case 93:f.shift();break;case 102:(v=f[0])[u||v.length]=!1,u=void 0;break;case 110:(v=f[0])[u||v.length]=null,u=void 0;break;case 116:(v=f[0])[u||v.length]=!0,u=void 0;break;case 123:v=f[0],f.unshift(v[u||v.length]={}),u=void 0;break;case 125:f.shift()}}if(l){if(1!==f.length)throw new Error;a=a[0]}else if(f.length)throw new Error;if(s){a=function t(e,r){var n=e[r];if(n&&"object"===(void 0===n?"undefined":g(n))){var i=null;for(var a in n)if(o.call(n,a)&&n!==e){var u=t(n,a);void 0!==u?n[a]=u:(i||(i=[]),i.push(a))}if(i)for(var c=i.length;--c>=0;)delete n[i[c]]}return s.call(e,r,n)}({"":a},"")}return a}}();void 0!==Sr&&Sr||(e.KJUR=Sr={}),void 0!==Sr.asn1&&Sr.asn1||(Sr.asn1={}),Sr.asn1.ASN1Util=new function(){this.integerToByteHex=function(t){var e=t.toString(16);return e.length%2==1&&(e="0"+e),e},this.bigIntToMinTwosComplementsHex=function(t){var e=t.toString(16);if("-"!=e.substr(0,1))e.length%2==1?e="0"+e:e.match(/^[0-7]/)||(e="00"+e);else{var r=e.substr(1).length;r%2==1?r+=1:e.match(/^[0-7]/)||(r+=2);for(var n="",i=0;i<r;i++)n+="f";e=new w(n,16).xor(t).add(w.ONE).toString(16).replace(/^-/,"")}return e},this.getPEMStringFromHex=function(t,e){return jr(t,e)},this.newObject=function(t){var e=Sr.asn1,r=e.ASN1Object,n=e.DERBoolean,i=e.DERInteger,o=e.DERBitString,s=e.DEROctetString,a=e.DERNull,u=e.DERObjectIdentifier,c=e.DEREnumerated,h=e.DERUTF8String,l=e.DERNumericString,f=e.DERPrintableString,g=e.DERTeletexString,d=e.DERIA5String,p=e.DERUTCTime,v=e.DERGeneralizedTime,y=e.DERVisibleString,m=e.DERBMPString,_=e.DERSequence,S=e.DERSet,b=e.DERTaggedObject,w=e.ASN1Util.newObject;if(t instanceof e.ASN1Object)return t;var F=Object.keys(t);if(1!=F.length)throw new Error("key of param shall be only one.");var E=F[0];if(-1==":asn1:bool:int:bitstr:octstr:null:oid:enum:utf8str:numstr:prnstr:telstr:ia5str:utctime:gentime:visstr:bmpstr:seq:set:tag:".indexOf(":"+E+":"))throw new Error("undefined key: "+E);if("bool"==E)return new n(t[E]);if("int"==E)return new i(t[E]);if("bitstr"==E)return new o(t[E]);if("octstr"==E)return new s(t[E]);if("null"==E)return new a(t[E]);if("oid"==E)return new u(t[E]);if("enum"==E)return new c(t[E]);if("utf8str"==E)return new h(t[E]);if("numstr"==E)return new l(t[E]);if("prnstr"==E)return new f(t[E]);if("telstr"==E)return new g(t[E]);if("ia5str"==E)return new d(t[E]);if("utctime"==E)return new p(t[E]);if("gentime"==E)return new v(t[E]);if("visstr"==E)return new y(t[E]);if("bmpstr"==E)return new m(t[E]);if("asn1"==E)return new r(t[E]);if("seq"==E){for(var x=t[E],A=[],k=0;k<x.length;k++){var P=w(x[k]);A.push(P)}return new _({array:A})}if("set"==E){for(x=t[E],A=[],k=0;k<x.length;k++){P=w(x[k]);A.push(P)}return new S({array:A})}if("tag"==E){var C=t[E];if("[object Array]"===Object.prototype.toString.call(C)&&3==C.length){var T=w(C[2]);return new b({tag:C[0],explicit:C[1],obj:T})}return new b(C)}},this.jsonToASN1HEX=function(t){return this.newObject(t).getEncodedHex()}},Sr.asn1.ASN1Util.oidHexToInt=function(t){for(var e="",r=parseInt(t.substr(0,2),16),n=(e=Math.floor(r/40)+"."+r%40,""),i=2;i<t.length;i+=2){var o=("00000000"+parseInt(t.substr(i,2),16).toString(2)).slice(-8);if(n+=o.substr(1,7),"0"==o.substr(0,1))e=e+"."+new w(n,2).toString(10),n=""}return e},Sr.asn1.ASN1Util.oidIntToHex=function(t){var e=function t(e){var r=e.toString(16);return 1==r.length&&(r="0"+r),r},r=function t(r){var n="",i=new w(r,10).toString(2),o=7-i.length%7;7==o&&(o=0);for(var s="",a=0;a<o;a++)s+="0";i=s+i;for(a=0;a<i.length-1;a+=7){var u=i.substr(a,7);a!=i.length-7&&(u="1"+u),n+=e(parseInt(u,2))}return n};if(!t.match(/^[0-9.]+$/))throw"malformed oid string: "+t;var n="",i=t.split("."),o=40*parseInt(i[0])+parseInt(i[1]);n+=e(o),i.splice(0,2);for(var s=0;s<i.length;s++)n+=r(i[s]);return n},Sr.asn1.ASN1Object=function(t){this.params=null,this.getLengthHexFromValue=function(){if(void 0===this.hV||null==this.hV)throw new Error("this.hV is null or undefined");if(this.hV.length%2==1)throw new Error("value hex must be even length: n="+"".length+",v="+this.hV);var t=this.hV.length/2,e=t.toString(16);if(e.length%2==1&&(e="0"+e),t<128)return e;var r=e.length/2;if(r>15)throw"ASN.1 length too long to represent by 8x: n = "+t.toString(16);return(128+r).toString(16)+e},this.getEncodedHex=function(){return(null==this.hTLV||this.isModified)&&(this.hV=this.getFreshValueHex(),this.hL=this.getLengthHexFromValue(),this.hTLV=this.hT+this.hL+this.hV,this.isModified=!1),this.hTLV},this.getValueHex=function(){return this.getEncodedHex(),this.hV},this.getFreshValueHex=function(){return""},this.setByParam=function(t){this.params=t},null!=t&&null!=t.tlv&&(this.hTLV=t.tlv,this.isModified=!1)},Sr.asn1.DERAbstractString=function(t){Sr.asn1.DERAbstractString.superclass.constructor.call(this);this.getString=function(){return this.s},this.setString=function(t){this.hTLV=null,this.isModified=!0,this.s=t,this.hV=Ir(this.s).toLowerCase()},this.setStringHex=function(t){this.hTLV=null,this.isModified=!0,this.s=null,this.hV=t},this.getFreshValueHex=function(){return this.hV},void 0!==t&&("string"==typeof t?this.setString(t):void 0!==t.str?this.setString(t.str):void 0!==t.hex&&this.setStringHex(t.hex))},Zr(Sr.asn1.DERAbstractString,Sr.asn1.ASN1Object),Sr.asn1.DERAbstractTime=function(t){Sr.asn1.DERAbstractTime.superclass.constructor.call(this);this.localDateToUTC=function(t){var e=t.getTime()+6e4*t.getTimezoneOffset();return new Date(e)},this.formatDate=function(t,e,r){var n=this.zeroPadding,i=this.localDateToUTC(t),o=String(i.getFullYear());"utc"==e&&(o=o.substr(2,2));var s=o+n(String(i.getMonth()+1),2)+n(String(i.getDate()),2)+n(String(i.getHours()),2)+n(String(i.getMinutes()),2)+n(String(i.getSeconds()),2);if(!0===r){var a=i.getMilliseconds();if(0!=a){var u=n(String(a),3);s=s+"."+(u=u.replace(/[0]+$/,""))}}return s+"Z"},this.zeroPadding=function(t,e){return t.length>=e?t:new Array(e-t.length+1).join("0")+t},this.getString=function(){return this.s},this.setString=function(t){this.hTLV=null,this.isModified=!0,this.s=t,this.hV=kr(t)},this.setByDateValue=function(t,e,r,n,i,o){var s=new Date(Date.UTC(t,e-1,r,n,i,o,0));this.setByDate(s)},this.getFreshValueHex=function(){return this.hV}},Zr(Sr.asn1.DERAbstractTime,Sr.asn1.ASN1Object),Sr.asn1.DERAbstractStructured=function(t){Sr.asn1.DERAbstractString.superclass.constructor.call(this);this.setByASN1ObjectArray=function(t){this.hTLV=null,this.isModified=!0,this.asn1Array=t},this.appendASN1Object=function(t){this.hTLV=null,this.isModified=!0,this.asn1Array.push(t)},this.asn1Array=new Array,void 0!==t&&void 0!==t.array&&(this.asn1Array=t.array)},Zr(Sr.asn1.DERAbstractStructured,Sr.asn1.ASN1Object),Sr.asn1.DERBoolean=function(t){Sr.asn1.DERBoolean.superclass.constructor.call(this),this.hT="01",this.hTLV=0==t?"010100":"0101ff"},Zr(Sr.asn1.DERBoolean,Sr.asn1.ASN1Object),Sr.asn1.DERInteger=function(t){Sr.asn1.DERInteger.superclass.constructor.call(this),this.hT="02",this.setByBigInteger=function(t){this.hTLV=null,this.isModified=!0,this.hV=Sr.asn1.ASN1Util.bigIntToMinTwosComplementsHex(t)},this.setByInteger=function(t){var e=new w(String(t),10);this.setByBigInteger(e)},this.setValueHex=function(t){this.hV=t},this.getFreshValueHex=function(){return this.hV},void 0!==t&&(void 0!==t.bigint?this.setByBigInteger(t.bigint):void 0!==t.int?this.setByInteger(t.int):"number"==typeof t?this.setByInteger(t):void 0!==t.hex&&this.setValueHex(t.hex))},Zr(Sr.asn1.DERInteger,Sr.asn1.ASN1Object),Sr.asn1.DERBitString=function(t){if(void 0!==t&&void 0!==t.obj){var e=Sr.asn1.ASN1Util.newObject(t.obj);t.hex="00"+e.getEncodedHex()}Sr.asn1.DERBitString.superclass.constructor.call(this),this.hT="03",this.setHexValueIncludingUnusedBits=function(t){this.hTLV=null,this.isModified=!0,this.hV=t},this.setUnusedBitsAndHexValue=function(t,e){if(t<0||7<t)throw"unused bits shall be from 0 to 7: u = "+t;var r="0"+t;this.hTLV=null,this.isModified=!0,this.hV=r+e},this.setByBinaryString=function(t){var e=8-(t=t.replace(/0+$/,"")).length%8;8==e&&(e=0);for(var r=0;r<=e;r++)t+="0";var n="";for(r=0;r<t.length-1;r+=8){var i=t.substr(r,8),o=parseInt(i,2).toString(16);1==o.length&&(o="0"+o),n+=o}this.hTLV=null,this.isModified=!0,this.hV="0"+e+n},this.setByBooleanArray=function(t){for(var e="",r=0;r<t.length;r++)1==t[r]?e+="1":e+="0";this.setByBinaryString(e)},this.newFalseArray=function(t){for(var e=new Array(t),r=0;r<t;r++)e[r]=!1;return e},this.getFreshValueHex=function(){return this.hV},void 0!==t&&("string"==typeof t&&t.toLowerCase().match(/^[0-9a-f]+$/)?this.setHexValueIncludingUnusedBits(t):void 0!==t.hex?this.setHexValueIncludingUnusedBits(t.hex):void 0!==t.bin?this.setByBinaryString(t.bin):void 0!==t.array&&this.setByBooleanArray(t.array))},Zr(Sr.asn1.DERBitString,Sr.asn1.ASN1Object),Sr.asn1.DEROctetString=function(t){if(void 0!==t&&void 0!==t.obj){var e=Sr.asn1.ASN1Util.newObject(t.obj);t.hex=e.getEncodedHex()}Sr.asn1.DEROctetString.superclass.constructor.call(this,t),this.hT="04"},Zr(Sr.asn1.DEROctetString,Sr.asn1.DERAbstractString),Sr.asn1.DERNull=function(){Sr.asn1.DERNull.superclass.constructor.call(this),this.hT="05",this.hTLV="0500"},Zr(Sr.asn1.DERNull,Sr.asn1.ASN1Object),Sr.asn1.DERObjectIdentifier=function(t){Sr.asn1.DERObjectIdentifier.superclass.constructor.call(this),this.hT="06",this.setValueHex=function(t){this.hTLV=null,this.isModified=!0,this.s=null,this.hV=t},this.setValueOidString=function(t){var e=function r(t){var e=function t(e){var r=e.toString(16);return 1==r.length&&(r="0"+r),r},r=function t(r){var n="",i=parseInt(r,10).toString(2),o=7-i.length%7;7==o&&(o=0);for(var s="",a=0;a<o;a++)s+="0";i=s+i;for(a=0;a<i.length-1;a+=7){var u=i.substr(a,7);a!=i.length-7&&(u="1"+u),n+=e(parseInt(u,2))}return n};try{if(!t.match(/^[0-9.]+$/))return null;var n="",i=t.split("."),o=40*parseInt(i[0],10)+parseInt(i[1],10);n+=e(o),i.splice(0,2);for(var s=0;s<i.length;s++)n+=r(i[s]);return n}catch(t){return null}}(t);if(null==e)throw new Error("malformed oid string: "+t);this.hTLV=null,this.isModified=!0,this.s=null,this.hV=e},this.setValueName=function(t){var e=Sr.asn1.x509.OID.name2oid(t);if(""===e)throw new Error("DERObjectIdentifier oidName undefined: "+t);this.setValueOidString(e)},this.setValueNameOrOid=function(t){t.match(/^[0-2].[0-9.]+$/)?this.setValueOidString(t):this.setValueName(t)},this.getFreshValueHex=function(){return this.hV},this.setByParam=function(t){"string"==typeof t?this.setValueNameOrOid(t):void 0!==t.oid?this.setValueNameOrOid(t.oid):void 0!==t.name?this.setValueNameOrOid(t.name):void 0!==t.hex&&this.setValueHex(t.hex)},void 0!==t&&this.setByParam(t)},Zr(Sr.asn1.DERObjectIdentifier,Sr.asn1.ASN1Object),Sr.asn1.DEREnumerated=function(t){Sr.asn1.DEREnumerated.superclass.constructor.call(this),this.hT="0a",this.setByBigInteger=function(t){this.hTLV=null,this.isModified=!0,this.hV=Sr.asn1.ASN1Util.bigIntToMinTwosComplementsHex(t)},this.setByInteger=function(t){var e=new w(String(t),10);this.setByBigInteger(e)},this.setValueHex=function(t){this.hV=t},this.getFreshValueHex=function(){return this.hV},void 0!==t&&(void 0!==t.int?this.setByInteger(t.int):"number"==typeof t?this.setByInteger(t):void 0!==t.hex&&this.setValueHex(t.hex))},Zr(Sr.asn1.DEREnumerated,Sr.asn1.ASN1Object),Sr.asn1.DERUTF8String=function(t){Sr.asn1.DERUTF8String.superclass.constructor.call(this,t),this.hT="0c"},Zr(Sr.asn1.DERUTF8String,Sr.asn1.DERAbstractString),Sr.asn1.DERNumericString=function(t){Sr.asn1.DERNumericString.superclass.constructor.call(this,t),this.hT="12"},Zr(Sr.asn1.DERNumericString,Sr.asn1.DERAbstractString),Sr.asn1.DERPrintableString=function(t){Sr.asn1.DERPrintableString.superclass.constructor.call(this,t),this.hT="13"},Zr(Sr.asn1.DERPrintableString,Sr.asn1.DERAbstractString),Sr.asn1.DERTeletexString=function(t){Sr.asn1.DERTeletexString.superclass.constructor.call(this,t),this.hT="14"},Zr(Sr.asn1.DERTeletexString,Sr.asn1.DERAbstractString),Sr.asn1.DERIA5String=function(t){Sr.asn1.DERIA5String.superclass.constructor.call(this,t),this.hT="16"},Zr(Sr.asn1.DERIA5String,Sr.asn1.DERAbstractString),Sr.asn1.DERVisibleString=function(t){Sr.asn1.DERIA5String.superclass.constructor.call(this,t),this.hT="1a"},Zr(Sr.asn1.DERVisibleString,Sr.asn1.DERAbstractString),Sr.asn1.DERBMPString=function(t){Sr.asn1.DERBMPString.superclass.constructor.call(this,t),this.hT="1e"},Zr(Sr.asn1.DERBMPString,Sr.asn1.DERAbstractString),Sr.asn1.DERUTCTime=function(t){Sr.asn1.DERUTCTime.superclass.constructor.call(this,t),this.hT="17",this.setByDate=function(t){this.hTLV=null,this.isModified=!0,this.date=t,this.s=this.formatDate(this.date,"utc"),this.hV=kr(this.s)},this.getFreshValueHex=function(){return void 0===this.date&&void 0===this.s&&(this.date=new Date,this.s=this.formatDate(this.date,"utc"),this.hV=kr(this.s)),this.hV},void 0!==t&&(void 0!==t.str?this.setString(t.str):"string"==typeof t&&t.match(/^[0-9]{12}Z$/)?this.setString(t):void 0!==t.hex?this.setStringHex(t.hex):void 0!==t.date&&this.setByDate(t.date))},Zr(Sr.asn1.DERUTCTime,Sr.asn1.DERAbstractTime),Sr.asn1.DERGeneralizedTime=function(t){Sr.asn1.DERGeneralizedTime.superclass.constructor.call(this,t),this.hT="18",this.withMillis=!1,this.setByDate=function(t){this.hTLV=null,this.isModified=!0,this.date=t,this.s=this.formatDate(this.date,"gen",this.withMillis),this.hV=kr(this.s)},this.getFreshValueHex=function(){return void 0===this.date&&void 0===this.s&&(this.date=new Date,this.s=this.formatDate(this.date,"gen",this.withMillis),this.hV=kr(this.s)),this.hV},void 0!==t&&(void 0!==t.str?this.setString(t.str):"string"==typeof t&&t.match(/^[0-9]{14}Z$/)?this.setString(t):void 0!==t.hex?this.setStringHex(t.hex):void 0!==t.date&&this.setByDate(t.date),!0===t.millis&&(this.withMillis=!0))},Zr(Sr.asn1.DERGeneralizedTime,Sr.asn1.DERAbstractTime),Sr.asn1.DERSequence=function(t){Sr.asn1.DERSequence.superclass.constructor.call(this,t),this.hT="30",this.getFreshValueHex=function(){for(var t="",e=0;e<this.asn1Array.length;e++){t+=this.asn1Array[e].getEncodedHex()}return this.hV=t,this.hV}},Zr(Sr.asn1.DERSequence,Sr.asn1.DERAbstractStructured),Sr.asn1.DERSet=function(t){Sr.asn1.DERSet.superclass.constructor.call(this,t),this.hT="31",this.sortFlag=!0,this.getFreshValueHex=function(){for(var t=new Array,e=0;e<this.asn1Array.length;e++){var r=this.asn1Array[e];t.push(r.getEncodedHex())}return 1==this.sortFlag&&t.sort(),this.hV=t.join(""),this.hV},void 0!==t&&void 0!==t.sortflag&&0==t.sortflag&&(this.sortFlag=!1)},Zr(Sr.asn1.DERSet,Sr.asn1.DERAbstractStructured),Sr.asn1.DERTaggedObject=function(t){Sr.asn1.DERTaggedObject.superclass.constructor.call(this);var e=Sr.asn1;this.hT="a0",this.hV="",this.isExplicit=!0,this.asn1Object=null,this.setASN1Object=function(t,e,r){this.hT=e,this.isExplicit=t,this.asn1Object=r,this.isExplicit?(this.hV=this.asn1Object.getEncodedHex(),this.hTLV=null,this.isModified=!0):(this.hV=null,this.hTLV=r.getEncodedHex(),this.hTLV=this.hTLV.replace(/^../,e),this.isModified=!1)},this.getFreshValueHex=function(){return this.hV},this.setByParam=function(t){null!=t.tag&&(this.hT=t.tag),null!=t.explicit&&(this.isExplicit=t.explicit),null!=t.tage&&(this.hT=t.tage,this.isExplicit=!0),null!=t.tagi&&(this.hT=t.tagi,this.isExplicit=!1),null!=t.obj&&(t.obj instanceof e.ASN1Object?(this.asn1Object=t.obj,this.setASN1Object(this.isExplicit,this.hT,this.asn1Object)):"object"==g(t.obj)&&(this.asn1Object=e.ASN1Util.newObject(t.obj),this.setASN1Object(this.isExplicit,this.hT,this.asn1Object)))},null!=t&&this.setByParam(t)},Zr(Sr.asn1.DERTaggedObject,Sr.asn1.ASN1Object);var Sr,br,wr,Fr=new function(){};function Er(t){for(var e=new Array,r=0;r<t.length;r++)e[r]=t.charCodeAt(r);return e}function xr(t){for(var e="",r=0;r<t.length;r++)e+=String.fromCharCode(t[r]);return e}function Ar(t){for(var e="",r=0;r<t.length;r++){var n=t[r].toString(16);1==n.length&&(n="0"+n),e+=n}return e}function kr(t){return Ar(Er(t))}function Pr(t){return t=(t=(t=t.replace(/\=/g,"")).replace(/\+/g,"-")).replace(/\//g,"_")}function Cr(t){return t.length%4==2?t+="==":t.length%4==3&&(t+="="),t=(t=t.replace(/-/g,"+")).replace(/_/g,"/")}function Tr(t){return t.length%2==1&&(t="0"+t),Pr(_(t))}function Rr(t){return S(Cr(t))}function Ir(t){return Kr(Gr(t))}function Dr(t){return decodeURIComponent(qr(t))}function Lr(t){for(var e="",r=0;r<t.length-1;r+=2)e+=String.fromCharCode(parseInt(t.substr(r,2),16));return e}function Nr(t){for(var e="",r=0;r<t.length;r++)e+=("0"+t.charCodeAt(r).toString(16)).slice(-2);return e}function Ur(t){return _(t)}function Br(t){var e=Ur(t).replace(/(.{64})/g,"$1\r\n");return e=e.replace(/\r\n$/,"")}function Or(t){return S(t.replace(/[^0-9A-Za-z\/+=]*/g,""))}function jr(t,e){return"-----BEGIN "+e+"-----\r\n"+Br(t)+"\r\n-----END "+e+"-----\r\n"}function Mr(t,e){if(-1==t.indexOf("-----BEGIN "))throw"can't find PEM header: "+e;return Or(t=void 0!==e?(t=t.replace(new RegExp("^[^]*-----BEGIN "+e+"-----"),"")).replace(new RegExp("-----END "+e+"-----[^]*$"),""):(t=t.replace(/^[^]*-----BEGIN [^-]+-----/,"")).replace(/-----END [^-]+-----[^]*$/,""))}function Hr(t){var e,r,n,i,o,s,a,u,c,h,l;if(l=t.match(/^(\d{2}|\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(|\.\d+)Z$/))return u=l[1],e=parseInt(u),2===u.length&&(50<=e&&e<100?e=1900+e:0<=e&&e<50&&(e=2e3+e)),r=parseInt(l[2])-1,n=parseInt(l[3]),i=parseInt(l[4]),o=parseInt(l[5]),s=parseInt(l[6]),a=0,""!==(c=l[7])&&(h=(c.substr(1)+"00").substr(0,3),a=parseInt(h)),Date.UTC(e,r,n,i,o,s,a);throw"unsupported zulu format: "+t}function Vr(t){return~~(Hr(t)/1e3)}function Kr(t){return t.replace(/%/g,"")}function qr(t){return t.replace(/(..)/g,"%$1")}function Jr(t){var e="malformed IPv6 address";if(!t.match(/^[0-9A-Fa-f:]+$/))throw e;var r=(t=t.toLowerCase()).split(":").length-1;if(r<2)throw e;var n=":".repeat(7-r+2),i=(t=t.replace("::",n)).split(":");if(8!=i.length)throw e;for(var o=0;o<8;o++)i[o]=("0000"+i[o]).slice(-4);return i.join("")}function Wr(t){if(!t.match(/^[0-9A-Fa-f]{32}$/))throw"malformed IPv6 address octet";for(var e=(t=t.toLowerCase()).match(/.{1,4}/g),r=0;r<8;r++)e[r]=e[r].replace(/^0+/,""),""==e[r]&&(e[r]="0");var n=(t=":"+e.join(":")+":").match(/:(0:){2,}/g);if(null===n)return t.slice(1,-1);var i="";for(r=0;r<n.length;r++)n[r].length>i.length&&(i=n[r]);return(t=t.replace(i,"::")).slice(1,-1)}function zr(t){var e="malformed hex value";if(!t.match(/^([0-9A-Fa-f][0-9A-Fa-f]){1,}$/))throw e;if(8!=t.length)return 32==t.length?Wr(t):t;try{return parseInt(t.substr(0,2),16)+"."+parseInt(t.substr(2,2),16)+"."+parseInt(t.substr(4,2),16)+"."+parseInt(t.substr(6,2),16)}catch(t){throw e}}function Yr(t){return t.match(/.{4}/g).map((function e(t){var e=parseInt(t.substr(0,2),16),r=parseInt(t.substr(2),16);if(0==e&r<128)return String.fromCharCode(r);if(e<8){var n=128|63&r;return Dr((192|(7&e)<<3|(192&r)>>6).toString(16)+n.toString(16))}n=128|(15&e)<<2|(192&r)>>6;var i=128|63&r;return Dr((224|(240&e)>>4).toString(16)+n.toString(16)+i.toString(16))})).join("")}function Gr(t){for(var e=encodeURIComponent(t),r="",n=0;n<e.length;n++)"%"==e[n]?(r+=e.substr(n,3),n+=2):r=r+"%"+kr(e[n]);return r}function Xr(t){return!(t.length%2!=0||!t.match(/^[0-9a-f]+$/)&&!t.match(/^[0-9A-F]+$/))}function $r(t){return t.length%2==1?"0"+t:t.substr(0,1)>"7"?"00"+t:t}Fr.getLblen=function(t,e){if("8"!=t.substr(e+2,1))return 1;var r=parseInt(t.substr(e+3,1));return 0==r?-1:0<r&&r<10?r+1:-2},Fr.getL=function(t,e){var r=Fr.getLblen(t,e);return r<1?"":t.substr(e+2,2*r)},Fr.getVblen=function(t,e){var r;return""==(r=Fr.getL(t,e))?-1:("8"===r.substr(0,1)?new w(r.substr(2),16):new w(r,16)).intValue()},Fr.getVidx=function(t,e){var r=Fr.getLblen(t,e);return r<0?r:e+2*(r+1)},Fr.getV=function(t,e){var r=Fr.getVidx(t,e),n=Fr.getVblen(t,e);return t.substr(r,2*n)},Fr.getTLV=function(t,e){return t.substr(e,2)+Fr.getL(t,e)+Fr.getV(t,e)},Fr.getTLVblen=function(t,e){return 2+2*Fr.getLblen(t,e)+2*Fr.getVblen(t,e)},Fr.getNextSiblingIdx=function(t,e){return Fr.getVidx(t,e)+2*Fr.getVblen(t,e)},Fr.getChildIdx=function(t,e){var r,n,i,o=Fr,s=[];r=o.getVidx(t,e),n=2*o.getVblen(t,e),"03"==t.substr(e,2)&&(r+=2,n-=2),i=0;for(var a=r;i<=n;){var u=o.getTLVblen(t,a);if((i+=u)<=n&&s.push(a),a+=u,i>=n)break}return s},Fr.getNthChildIdx=function(t,e,r){return Fr.getChildIdx(t,e)[r]},Fr.getIdxbyList=function(t,e,r,n){var i,o,s=Fr;return 0==r.length?void 0!==n&&t.substr(e,2)!==n?-1:e:(i=r.shift())>=(o=s.getChildIdx(t,e)).length?-1:s.getIdxbyList(t,o[i],r,n)},Fr.getIdxbyListEx=function(t,e,r,n){var i,o,s=Fr;if(0==r.length)return void 0!==n&&t.substr(e,2)!==n?-1:e;i=r.shift(),o=s.getChildIdx(t,e);for(var a=0,u=0;u<o.length;u++){var c=t.substr(o[u],2);if("number"==typeof i&&!s.isContextTag(c)&&a==i||"string"==typeof i&&s.isContextTag(c,i))return s.getIdxbyListEx(t,o[u],r,n);s.isContextTag(c)||a++}return-1},Fr.getTLVbyList=function(t,e,r,n){var i=Fr,o=i.getIdxbyList(t,e,r,n);return-1==o||o>=t.length?null:i.getTLV(t,o)},Fr.getTLVbyListEx=function(t,e,r,n){var i=Fr,o=i.getIdxbyListEx(t,e,r,n);return-1==o?null:i.getTLV(t,o)},Fr.getVbyList=function(t,e,r,n,i){var o,s,a=Fr;return-1==(o=a.getIdxbyList(t,e,r,n))||o>=t.length?null:(s=a.getV(t,o),!0===i&&(s=s.substr(2)),s)},Fr.getVbyListEx=function(t,e,r,n,i){var o,s,a=Fr;return-1==(o=a.getIdxbyListEx(t,e,r,n))?null:(s=a.getV(t,o),"03"==t.substr(o,2)&&!1!==i&&(s=s.substr(2)),s)},Fr.getInt=function(t,e,r){null==r&&(r=-1);try{var n=t.substr(e,2);if("02"!=n&&"03"!=n)return r;var i=Fr.getV(t,e);return"02"==n?parseInt(i,16):function o(t){try{var e=t.substr(0,2);if("00"==e)return parseInt(t.substr(2),16);var r=parseInt(e,16),n=t.substr(2),i=parseInt(n,16).toString(2);return"0"==i&&(i="00000000"),i=i.slice(0,0-r),parseInt(i,2)}catch(t){return-1}}(i)}catch(t){return r}},Fr.getOID=function(t,e,r){null==r&&(r=null);try{return"06"!=t.substr(e,2)?r:function n(t){if(!Xr(t))return null;try{var e=[],r=t.substr(0,2),n=parseInt(r,16);e[0]=new String(Math.floor(n/40)),e[1]=new String(n%40);for(var i=t.substr(2),o=[],s=0;s<i.length/2;s++)o.push(parseInt(i.substr(2*s,2),16));var a=[],u="";for(s=0;s<o.length;s++)128&o[s]?u+=Qr((127&o[s]).toString(2),7):(u+=Qr((127&o[s]).toString(2),7),a.push(new String(parseInt(u,2))),u="");var c=e.join(".");return a.length>0&&(c=c+"."+a.join(".")),c}catch(t){return null}}(Fr.getV(t,e))}catch(t){return r}},Fr.getOIDName=function(t,e,r){null==r&&(r=null);try{var n=Fr.getOID(t,e,r);if(n==r)return r;var i=Sr.asn1.x509.OID.oid2name(n);return""==i?n:i}catch(t){return r}},Fr.getString=function(t,e,r){null==r&&(r=null);try{return Lr(Fr.getV(t,e))}catch(t){return r}},Fr.hextooidstr=function(t){var e=function t(e,r){return e.length>=r?e:new Array(r-e.length+1).join("0")+e},r=[],n=t.substr(0,2),i=parseInt(n,16);r[0]=new String(Math.floor(i/40)),r[1]=new String(i%40);for(var o=t.substr(2),s=[],a=0;a<o.length/2;a++)s.push(parseInt(o.substr(2*a,2),16));var u=[],c="";for(a=0;a<s.length;a++)128&s[a]?c+=e((127&s[a]).toString(2),7):(c+=e((127&s[a]).toString(2),7),u.push(new String(parseInt(c,2))),c="");var h=r.join(".");return u.length>0&&(h=h+"."+u.join(".")),h},Fr.dump=function(t,e,r,n){var i=Fr,o=i.getV,s=i.dump,a=i.getChildIdx,u=t;t instanceof Sr.asn1.ASN1Object&&(u=t.getEncodedHex());var c=function t(e,r){return e.length<=2*r?e:e.substr(0,r)+"..(total "+e.length/2+"bytes).."+e.substr(e.length-r,r)};void 0===e&&(e={ommit_long_octet:32}),void 0===r&&(r=0),void 0===n&&(n="");var h,l=e.ommit_long_octet;if("01"==(h=u.substr(r,2)))return"00"==(f=o(u,r))?n+"BOOLEAN FALSE\n":n+"BOOLEAN TRUE\n";if("02"==h)return n+"INTEGER "+c(f=o(u,r),l)+"\n";if("03"==h){var f=o(u,r);if(i.isASN1HEX(f.substr(2))){var g=n+"BITSTRING, encapsulates\n";return g+=s(f.substr(2),e,0,n+"  ")}return n+"BITSTRING "+c(f,l)+"\n"}if("04"==h){f=o(u,r);if(i.isASN1HEX(f)){g=n+"OCTETSTRING, encapsulates\n";return g+=s(f,e,0,n+"  ")}return n+"OCTETSTRING "+c(f,l)+"\n"}if("05"==h)return n+"NULL\n";if("06"==h){var d=o(u,r),p=Sr.asn1.ASN1Util.oidHexToInt(d),v=Sr.asn1.x509.OID.oid2name(p),y=p.replace(/\./g," ");return""!=v?n+"ObjectIdentifier "+v+" ("+y+")\n":n+"ObjectIdentifier ("+y+")\n"}if("0a"==h)return n+"ENUMERATED "+parseInt(o(u,r))+"\n";if("0c"==h)return n+"UTF8String '"+Dr(o(u,r))+"'\n";if("13"==h)return n+"PrintableString '"+Dr(o(u,r))+"'\n";if("14"==h)return n+"TeletexString '"+Dr(o(u,r))+"'\n";if("16"==h)return n+"IA5String '"+Dr(o(u,r))+"'\n";if("17"==h)return n+"UTCTime "+Dr(o(u,r))+"\n";if("18"==h)return n+"GeneralizedTime "+Dr(o(u,r))+"\n";if("1a"==h)return n+"VisualString '"+Dr(o(u,r))+"'\n";if("1e"==h)return n+"BMPString '"+Yr(o(u,r))+"'\n";if("30"==h){if("3000"==u.substr(r,4))return n+"SEQUENCE {}\n";g=n+"SEQUENCE\n";var m=e;if((2==(b=a(u,r)).length||3==b.length)&&"06"==u.substr(b[0],2)&&"04"==u.substr(b[b.length-1],2)){v=i.oidname(o(u,b[0]));var _=JSON.parse(JSON.stringify(e));_.x509ExtName=v,m=_}for(var S=0;S<b.length;S++)g+=s(u,m,b[S],n+"  ");return g}if("31"==h){g=n+"SET\n";var b=a(u,r);for(S=0;S<b.length;S++)g+=s(u,e,b[S],n+"  ");return g}if(0!=(128&(h=parseInt(h,16)))){var w=31&h;if(0!=(32&h)){for(g=n+"["+w+"]\n",b=a(u,r),S=0;S<b.length;S++)g+=s(u,e,b[S],n+"  ");return g}f=o(u,r);if(Fr.isASN1HEX(f)){var g=n+"["+w+"]\n";return g+=s(f,e,0,n+"  ")}return("68747470"==f.substr(0,8)||"subjectAltName"===e.x509ExtName&&2==w)&&(f=Dr(f)),g=n+"["+w+"] "+f+"\n"}return n+"UNKNOWN("+h+") "+o(u,r)+"\n"},Fr.isContextTag=function(t,e){var r,n;t=t.toLowerCase();try{r=parseInt(t,16)}catch(t){return-1}if(void 0===e)return 128==(192&r);try{return null!=e.match(/^\[[0-9]+\]$/)&&(!((n=parseInt(e.substr(1,e.length-1),10))>31)&&(128==(192&r)&&(31&r)==n))}catch(t){return!1}},Fr.isASN1HEX=function(t){var e=Fr;if(t.length%2==1)return!1;var r=e.getVblen(t,0),n=t.substr(0,2),i=e.getL(t,0);return t.length-n.length-i.length==2*r},Fr.checkStrictDER=function(t,e,r,n,i){var o=Fr;if(void 0===r){if("string"!=typeof t)throw new Error("not hex string");if(t=t.toLowerCase(),!Sr.lang.String.isHex(t))throw new Error("not hex string");r=t.length,i=(n=t.length/2)<128?1:Math.ceil(n.toString(16))+1}if(o.getL(t,e).length>2*i)throw new Error("L of TLV too long: idx="+e);var s=o.getVblen(t,e);if(s>n)throw new Error("value of L too long than hex: idx="+e);var a=o.getTLV(t,e),u=a.length-2-o.getL(t,e).length;if(u!==2*s)throw new Error("V string length and L's value not the same:"+u+"/"+2*s);if(0===e&&t.length!=a.length)throw new Error("total length and TLV length unmatch:"+t.length+"!="+a.length);var c=t.substr(e,2);if("02"===c){var h=o.getVidx(t,e);if("00"==t.substr(h,2)&&t.charCodeAt(h+2)<56)throw new Error("not least zeros for DER INTEGER")}if(32&parseInt(c,16)){for(var l=o.getVblen(t,e),f=0,g=o.getChildIdx(t,e),d=0;d<g.length;d++){f+=o.getTLV(t,g[d]).length,o.checkStrictDER(t,g[d],r,n,i)}if(2*l!=f)throw new Error("sum of children's TLV length and L unmatch: "+2*l+"!="+f)}},Fr.oidname=function(t){var e=Sr.asn1;Sr.lang.String.isHex(t)&&(t=e.ASN1Util.oidHexToInt(t));var r=e.x509.OID.oid2name(t);return""===r&&(r=t),r},void 0!==Sr&&Sr||(e.KJUR=Sr={}),void 0!==Sr.lang&&Sr.lang||(Sr.lang={}),Sr.lang.String=function(){},"function"==typeof t?(e.utf8tob64u=br=function e(r){return Pr(t.from(r,"utf8").toString("base64"))},e.b64utoutf8=wr=function e(r){return t.from(Cr(r),"base64").toString("utf8")}):(e.utf8tob64u=br=function t(e){return Tr(Kr(Gr(e)))},e.b64utoutf8=wr=function t(e){return decodeURIComponent(qr(Rr(e)))}),Sr.lang.String.isInteger=function(t){return!!t.match(/^[0-9]+$/)||!!t.match(/^-[0-9]+$/)},Sr.lang.String.isHex=function(t){return Xr(t)},Sr.lang.String.isBase64=function(t){return!(!(t=t.replace(/\s+/g,"")).match(/^[0-9A-Za-z+\/]+={0,3}$/)||t.length%4!=0)},Sr.lang.String.isBase64URL=function(t){return!t.match(/[+/=]/)&&(t=Cr(t),Sr.lang.String.isBase64(t))},Sr.lang.String.isIntegerArray=function(t){return!!(t=t.replace(/\s+/g,"")).match(/^\[[0-9,]+\]$/)},Sr.lang.String.isPrintable=function(t){return null!==t.match(/^[0-9A-Za-z '()+,-./:=?]*$/)},Sr.lang.String.isIA5=function(t){return null!==t.match(/^[\x20-\x21\x23-\x7f]*$/)},Sr.lang.String.isMail=function(t){return null!==t.match(/^[A-Za-z0-9]{1}[A-Za-z0-9_.-]*@{1}[A-Za-z0-9_.-]{1,}\.[A-Za-z0-9]{1,}$/)};var Qr=function t(e,r,n){return null==n&&(n="0"),e.length>=r?e:new Array(r-e.length+1).join(n)+e};function Zr(t,e){var r=function t(){};r.prototype=e.prototype,t.prototype=new r,t.prototype.constructor=t,t.superclass=e.prototype,e.prototype.constructor==Object.prototype.constructor&&(e.prototype.constructor=e)}void 0!==Sr&&Sr||(e.KJUR=Sr={}),void 0!==Sr.crypto&&Sr.crypto||(Sr.crypto={}),Sr.crypto.Util=new function(){this.DIGESTINFOHEAD={sha1:"3021300906052b0e03021a05000414",sha224:"302d300d06096086480165030402040500041c",sha256:"3031300d060960864801650304020105000420",sha384:"3041300d060960864801650304020205000430",sha512:"3051300d060960864801650304020305000440",md2:"3020300c06082a864886f70d020205000410",md5:"3020300c06082a864886f70d020505000410",ripemd160:"3021300906052b2403020105000414"},this.DEFAULTPROVIDER={md5:"cryptojs",sha1:"cryptojs",sha224:"cryptojs",sha256:"cryptojs",sha384:"cryptojs",sha512:"cryptojs",ripemd160:"cryptojs",hmacmd5:"cryptojs",hmacsha1:"cryptojs",hmacsha224:"cryptojs",hmacsha256:"cryptojs",hmacsha384:"cryptojs",hmacsha512:"cryptojs",hmacripemd160:"cryptojs",MD5withRSA:"cryptojs/jsrsa",SHA1withRSA:"cryptojs/jsrsa",SHA224withRSA:"cryptojs/jsrsa",SHA256withRSA:"cryptojs/jsrsa",SHA384withRSA:"cryptojs/jsrsa",SHA512withRSA:"cryptojs/jsrsa",RIPEMD160withRSA:"cryptojs/jsrsa",MD5withECDSA:"cryptojs/jsrsa",SHA1withECDSA:"cryptojs/jsrsa",SHA224withECDSA:"cryptojs/jsrsa",SHA256withECDSA:"cryptojs/jsrsa",SHA384withECDSA:"cryptojs/jsrsa",SHA512withECDSA:"cryptojs/jsrsa",RIPEMD160withECDSA:"cryptojs/jsrsa",SHA1withDSA:"cryptojs/jsrsa",SHA224withDSA:"cryptojs/jsrsa",SHA256withDSA:"cryptojs/jsrsa",MD5withRSAandMGF1:"cryptojs/jsrsa",SHAwithRSAandMGF1:"cryptojs/jsrsa",SHA1withRSAandMGF1:"cryptojs/jsrsa",SHA224withRSAandMGF1:"cryptojs/jsrsa",SHA256withRSAandMGF1:"cryptojs/jsrsa",SHA384withRSAandMGF1:"cryptojs/jsrsa",SHA512withRSAandMGF1:"cryptojs/jsrsa",RIPEMD160withRSAandMGF1:"cryptojs/jsrsa"},this.CRYPTOJSMESSAGEDIGESTNAME={md5:v.algo.MD5,sha1:v.algo.SHA1,sha224:v.algo.SHA224,sha256:v.algo.SHA256,sha384:v.algo.SHA384,sha512:v.algo.SHA512,ripemd160:v.algo.RIPEMD160},this.getDigestInfoHex=function(t,e){if(void 0===this.DIGESTINFOHEAD[e])throw"alg not supported in Util.DIGESTINFOHEAD: "+e;return this.DIGESTINFOHEAD[e]+t},this.getPaddedDigestInfoHex=function(t,e,r){var n=this.getDigestInfoHex(t,e),i=r/4;if(n.length+22>i)throw"key is too short for SigAlg: keylen="+r+","+e;for(var o="0001",s="00"+n,a="",u=i-o.length-s.length,c=0;c<u;c+=2)a+="ff";return o+a+s},this.hashString=function(t,e){return new Sr.crypto.MessageDigest({alg:e}).digestString(t)},this.hashHex=function(t,e){return new Sr.crypto.MessageDigest({alg:e}).digestHex(t)},this.sha1=function(t){return this.hashString(t,"sha1")},this.sha256=function(t){return this.hashString(t,"sha256")},this.sha256Hex=function(t){return this.hashHex(t,"sha256")},this.sha512=function(t){return this.hashString(t,"sha512")},this.sha512Hex=function(t){return this.hashHex(t,"sha512")},this.isKey=function(t){return t instanceof Me||t instanceof Sr.crypto.DSA||t instanceof Sr.crypto.ECDSA}},Sr.crypto.Util.md5=function(t){return new Sr.crypto.MessageDigest({alg:"md5",prov:"cryptojs"}).digestString(t)},Sr.crypto.Util.ripemd160=function(t){return new Sr.crypto.MessageDigest({alg:"ripemd160",prov:"cryptojs"}).digestString(t)},Sr.crypto.Util.SECURERANDOMGEN=new Be,Sr.crypto.Util.getRandomHexOfNbytes=function(t){var e=new Array(t);return Sr.crypto.Util.SECURERANDOMGEN.nextBytes(e),Ar(e)},Sr.crypto.Util.getRandomBigIntegerOfNbytes=function(t){return new w(Sr.crypto.Util.getRandomHexOfNbytes(t),16)},Sr.crypto.Util.getRandomHexOfNbits=function(t){var e=t%8,r=new Array((t-e)/8+1);return Sr.crypto.Util.SECURERANDOMGEN.nextBytes(r),r[0]=(255<<e&255^255)&r[0],Ar(r)},Sr.crypto.Util.getRandomBigIntegerOfNbits=function(t){return new w(Sr.crypto.Util.getRandomHexOfNbits(t),16)},Sr.crypto.Util.getRandomBigIntegerZeroToMax=function(t){for(var e=t.bitLength();;){var r=Sr.crypto.Util.getRandomBigIntegerOfNbits(e);if(-1!=t.compareTo(r))return r}},Sr.crypto.Util.getRandomBigIntegerMinToMax=function(t,e){var r=t.compareTo(e);if(1==r)throw"biMin is greater than biMax";if(0==r)return t;var n=e.subtract(t);return Sr.crypto.Util.getRandomBigIntegerZeroToMax(n).add(t)},Sr.crypto.MessageDigest=function(t){this.setAlgAndProvider=function(t,e){if(null!==(t=Sr.crypto.MessageDigest.getCanonicalAlgName(t))&&void 0===e&&(e=Sr.crypto.Util.DEFAULTPROVIDER[t]),-1!=":md5:sha1:sha224:sha256:sha384:sha512:ripemd160:".indexOf(t)&&"cryptojs"==e){try{this.md=Sr.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[t].create()}catch(e){throw"setAlgAndProvider hash alg set fail alg="+t+"/"+e}this.updateString=function(t){this.md.update(t)},this.updateHex=function(t){var e=v.enc.Hex.parse(t);this.md.update(e)},this.digest=function(){return this.md.finalize().toString(v.enc.Hex)},this.digestString=function(t){return this.updateString(t),this.digest()},this.digestHex=function(t){return this.updateHex(t),this.digest()}}if(-1!=":sha256:".indexOf(t)&&"sjcl"==e){try{this.md=new sjcl.hash.sha256}catch(e){throw"setAlgAndProvider hash alg set fail alg="+t+"/"+e}this.updateString=function(t){this.md.update(t)},this.updateHex=function(t){var e=sjcl.codec.hex.toBits(t);this.md.update(e)},this.digest=function(){var t=this.md.finalize();return sjcl.codec.hex.fromBits(t)},this.digestString=function(t){return this.updateString(t),this.digest()},this.digestHex=function(t){return this.updateHex(t),this.digest()}}},this.updateString=function(t){throw"updateString(str) not supported for this alg/prov: "+this.algName+"/"+this.provName},this.updateHex=function(t){throw"updateHex(hex) not supported for this alg/prov: "+this.algName+"/"+this.provName},this.digest=function(){throw"digest() not supported for this alg/prov: "+this.algName+"/"+this.provName},this.digestString=function(t){throw"digestString(str) not supported for this alg/prov: "+this.algName+"/"+this.provName},this.digestHex=function(t){throw"digestHex(hex) not supported for this alg/prov: "+this.algName+"/"+this.provName},void 0!==t&&void 0!==t.alg&&(this.algName=t.alg,void 0===t.prov&&(this.provName=Sr.crypto.Util.DEFAULTPROVIDER[this.algName]),this.setAlgAndProvider(this.algName,this.provName))},Sr.crypto.MessageDigest.getCanonicalAlgName=function(t){return"string"==typeof t&&(t=(t=t.toLowerCase()).replace(/-/,"")),t},Sr.crypto.MessageDigest.getHashLength=function(t){var e=Sr.crypto.MessageDigest,r=e.getCanonicalAlgName(t);if(void 0===e.HASHLENGTH[r])throw"not supported algorithm: "+t;return e.HASHLENGTH[r]},Sr.crypto.MessageDigest.HASHLENGTH={md5:16,sha1:20,sha224:28,sha256:32,sha384:48,sha512:64,ripemd160:20},Sr.crypto.Mac=function(t){this.setAlgAndProvider=function(t,e){if(null==(t=t.toLowerCase())&&(t="hmacsha1"),"hmac"!=(t=t.toLowerCase()).substr(0,4))throw"setAlgAndProvider unsupported HMAC alg: "+t;void 0===e&&(e=Sr.crypto.Util.DEFAULTPROVIDER[t]),this.algProv=t+"/"+e;var r=t.substr(4);if(-1!=":md5:sha1:sha224:sha256:sha384:sha512:ripemd160:".indexOf(r)&&"cryptojs"==e){try{var n=Sr.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[r];this.mac=v.algo.HMAC.create(n,this.pass)}catch(t){throw"setAlgAndProvider hash alg set fail hashAlg="+r+"/"+t}this.updateString=function(t){this.mac.update(t)},this.updateHex=function(t){var e=v.enc.Hex.parse(t);this.mac.update(e)},this.doFinal=function(){return this.mac.finalize().toString(v.enc.Hex)},this.doFinalString=function(t){return this.updateString(t),this.doFinal()},this.doFinalHex=function(t){return this.updateHex(t),this.doFinal()}}},this.updateString=function(t){throw"updateString(str) not supported for this alg/prov: "+this.algProv},this.updateHex=function(t){throw"updateHex(hex) not supported for this alg/prov: "+this.algProv},this.doFinal=function(){throw"digest() not supported for this alg/prov: "+this.algProv},this.doFinalString=function(t){throw"digestString(str) not supported for this alg/prov: "+this.algProv},this.doFinalHex=function(t){throw"digestHex(hex) not supported for this alg/prov: "+this.algProv},this.setPassword=function(t){if("string"==typeof t){var e=t;return t.length%2!=1&&t.match(/^[0-9A-Fa-f]+$/)||(e=Nr(t)),void(this.pass=v.enc.Hex.parse(e))}if("object"!=(void 0===t?"undefined":g(t)))throw"KJUR.crypto.Mac unsupported password type: "+t;e=null;if(void 0!==t.hex){if(t.hex.length%2!=0||!t.hex.match(/^[0-9A-Fa-f]+$/))throw"Mac: wrong hex password: "+t.hex;e=t.hex}if(void 0!==t.utf8&&(e=Ir(t.utf8)),void 0!==t.rstr&&(e=Nr(t.rstr)),void 0!==t.b64&&(e=S(t.b64)),void 0!==t.b64u&&(e=Rr(t.b64u)),null==e)throw"KJUR.crypto.Mac unsupported password type: "+t;this.pass=v.enc.Hex.parse(e)},void 0!==t&&(void 0!==t.pass&&this.setPassword(t.pass),void 0!==t.alg&&(this.algName=t.alg,void 0===t.prov&&(this.provName=Sr.crypto.Util.DEFAULTPROVIDER[this.algName]),this.setAlgAndProvider(this.algName,this.provName)))},Sr.crypto.Signature=function(t){var e=null;if(this._setAlgNames=function(){var t=this.algName.match(/^(.+)with(.+)$/);t&&(this.mdAlgName=t[1].toLowerCase(),this.pubkeyAlgName=t[2].toLowerCase(),"rsaandmgf1"==this.pubkeyAlgName&&"sha"==this.mdAlgName&&(this.mdAlgName="sha1"))},this._zeroPaddingOfSignature=function(t,e){for(var r="",n=e/4-t.length,i=0;i<n;i++)r+="0";return r+t},this.setAlgAndProvider=function(t,e){if(this._setAlgNames(),"cryptojs/jsrsa"!=e)throw new Error("provider not supported: "+e);if(-1!=":md5:sha1:sha224:sha256:sha384:sha512:ripemd160:".indexOf(this.mdAlgName)){try{this.md=new Sr.crypto.MessageDigest({alg:this.mdAlgName})}catch(t){throw new Error("setAlgAndProvider hash alg set fail alg="+this.mdAlgName+"/"+t)}this.init=function(t,e){var r=null;try{r=void 0===e?tn.getKey(t):tn.getKey(t,e)}catch(t){throw"init failed:"+t}if(!0===r.isPrivate)this.prvKey=r,this.state="SIGN";else{if(!0!==r.isPublic)throw"init failed.:"+r;this.pubKey=r,this.state="VERIFY"}},this.updateString=function(t){this.md.updateString(t)},this.updateHex=function(t){this.md.updateHex(t)},this.sign=function(){if(this.sHashHex=this.md.digest(),void 0===this.prvKey&&void 0!==this.ecprvhex&&void 0!==this.eccurvename&&void 0!==Sr.crypto.ECDSA&&(this.prvKey=new Sr.crypto.ECDSA({curve:this.eccurvename,prv:this.ecprvhex})),this.prvKey instanceof Me&&"rsaandmgf1"===this.pubkeyAlgName)this.hSign=this.prvKey.signWithMessageHashPSS(this.sHashHex,this.mdAlgName,this.pssSaltLen);else if(this.prvKey instanceof Me&&"rsa"===this.pubkeyAlgName)this.hSign=this.prvKey.signWithMessageHash(this.sHashHex,this.mdAlgName);else if(this.prvKey instanceof Sr.crypto.ECDSA)this.hSign=this.prvKey.signWithMessageHash(this.sHashHex);else{if(!(this.prvKey instanceof Sr.crypto.DSA))throw"Signature: unsupported private key alg: "+this.pubkeyAlgName;this.hSign=this.prvKey.signWithMessageHash(this.sHashHex)}return this.hSign},this.signString=function(t){return this.updateString(t),this.sign()},this.signHex=function(t){return this.updateHex(t),this.sign()},this.verify=function(t){if(this.sHashHex=this.md.digest(),void 0===this.pubKey&&void 0!==this.ecpubhex&&void 0!==this.eccurvename&&void 0!==Sr.crypto.ECDSA&&(this.pubKey=new Sr.crypto.ECDSA({curve:this.eccurvename,pub:this.ecpubhex})),this.pubKey instanceof Me&&"rsaandmgf1"===this.pubkeyAlgName)return this.pubKey.verifyWithMessageHashPSS(this.sHashHex,t,this.mdAlgName,this.pssSaltLen);if(this.pubKey instanceof Me&&"rsa"===this.pubkeyAlgName)return this.pubKey.verifyWithMessageHash(this.sHashHex,t);if(void 0!==Sr.crypto.ECDSA&&this.pubKey instanceof Sr.crypto.ECDSA)return this.pubKey.verifyWithMessageHash(this.sHashHex,t);if(void 0!==Sr.crypto.DSA&&this.pubKey instanceof Sr.crypto.DSA)return this.pubKey.verifyWithMessageHash(this.sHashHex,t);throw"Signature: unsupported public key alg: "+this.pubkeyAlgName}}},this.init=function(t,e){throw"init(key, pass) not supported for this alg:prov="+this.algProvName},this.updateString=function(t){throw"updateString(str) not supported for this alg:prov="+this.algProvName},this.updateHex=function(t){throw"updateHex(hex) not supported for this alg:prov="+this.algProvName},this.sign=function(){throw"sign() not supported for this alg:prov="+this.algProvName},this.signString=function(t){throw"digestString(str) not supported for this alg:prov="+this.algProvName},this.signHex=function(t){throw"digestHex(hex) not supported for this alg:prov="+this.algProvName},this.verify=function(t){throw"verify(hSigVal) not supported for this alg:prov="+this.algProvName},this.initParams=t,void 0!==t&&(void 0!==t.alg&&(this.algName=t.alg,void 0===t.prov?this.provName=Sr.crypto.Util.DEFAULTPROVIDER[this.algName]:this.provName=t.prov,this.algProvName=this.algName+":"+this.provName,this.setAlgAndProvider(this.algName,this.provName),this._setAlgNames()),void 0!==t.psssaltlen&&(this.pssSaltLen=t.psssaltlen),void 0!==t.prvkeypem)){if(void 0!==t.prvkeypas)throw"both prvkeypem and prvkeypas parameters not supported";try{e=tn.getKey(t.prvkeypem);this.init(e)}catch(t){throw"fatal error to load pem private key: "+t}}},Sr.crypto.Cipher=function(t){},Sr.crypto.Cipher.encrypt=function(t,e,r){if(e instanceof Me&&e.isPublic){var n=Sr.crypto.Cipher.getAlgByKeyAndName(e,r);if("RSA"===n)return e.encrypt(t);if("RSAOAEP"===n)return e.encryptOAEP(t,"sha1");var i=n.match(/^RSAOAEP(\d+)$/);if(null!==i)return e.encryptOAEP(t,"sha"+i[1]);throw"Cipher.encrypt: unsupported algorithm for RSAKey: "+r}throw"Cipher.encrypt: unsupported key or algorithm"},Sr.crypto.Cipher.decrypt=function(t,e,r){if(e instanceof Me&&e.isPrivate){var n=Sr.crypto.Cipher.getAlgByKeyAndName(e,r);if("RSA"===n)return e.decrypt(t);if("RSAOAEP"===n)return e.decryptOAEP(t,"sha1");var i=n.match(/^RSAOAEP(\d+)$/);if(null!==i)return e.decryptOAEP(t,"sha"+i[1]);throw"Cipher.decrypt: unsupported algorithm for RSAKey: "+r}throw"Cipher.decrypt: unsupported key or algorithm"},Sr.crypto.Cipher.getAlgByKeyAndName=function(t,e){if(t instanceof Me){if(-1!=":RSA:RSAOAEP:RSAOAEP224:RSAOAEP256:RSAOAEP384:RSAOAEP512:".indexOf(e))return e;if(null==e)return"RSA";throw"getAlgByKeyAndName: not supported algorithm name for RSAKey: "+e}throw"getAlgByKeyAndName: not supported algorithm name: "+e},Sr.crypto.OID=new function(){this.oidhex2name={"2a864886f70d010101":"rsaEncryption","2a8648ce3d0201":"ecPublicKey","2a8648ce380401":"dsa","2a8648ce3d030107":"secp256r1","2b8104001f":"secp192k1","2b81040021":"secp224r1","2b8104000a":"secp256k1","2b81040023":"secp521r1","2b81040022":"secp384r1","2a8648ce380403":"SHA1withDSA","608648016503040301":"SHA224withDSA","608648016503040302":"SHA256withDSA"}},void 0!==Sr&&Sr||(e.KJUR=Sr={}),void 0!==Sr.crypto&&Sr.crypto||(Sr.crypto={}),Sr.crypto.ECDSA=function(t){var e=Error,r=w,n=Ve,i=Sr.crypto.ECDSA,o=Sr.crypto.ECParameterDB,s=i.getName,a=Fr,u=a.getVbyListEx,c=a.isASN1HEX,h=new Be;this.type="EC",this.isPrivate=!1,this.isPublic=!1,this.getBigRandom=function(t){return new r(t.bitLength(),h).mod(t.subtract(r.ONE)).add(r.ONE)},this.setNamedCurve=function(t){this.ecparams=o.getByName(t),this.prvKeyHex=null,this.pubKeyHex=null,this.curveName=t},this.setPrivateKeyHex=function(t){this.isPrivate=!0,this.prvKeyHex=t},this.setPublicKeyHex=function(t){this.isPublic=!0,this.pubKeyHex=t},this.getPublicKeyXYHex=function(){var t=this.pubKeyHex;if("04"!==t.substr(0,2))throw"this method supports uncompressed format(04) only";var e=this.ecparams.keylen/4;if(t.length!==2+2*e)throw"malformed public key hex length";var r={};return r.x=t.substr(2,e),r.y=t.substr(2+e),r},this.getShortNISTPCurveName=function(){var t=this.curveName;return"secp256r1"===t||"NIST P-256"===t||"P-256"===t||"prime256v1"===t?"P-256":"secp384r1"===t||"NIST P-384"===t||"P-384"===t?"P-384":null},this.generateKeyPairHex=function(){var t=this.ecparams.n,e=this.getBigRandom(t),r=this.ecparams.G.multiply(e),n=r.getX().toBigInteger(),i=r.getY().toBigInteger(),o=this.ecparams.keylen/4,s=("0000000000"+e.toString(16)).slice(-o),a="04"+("0000000000"+n.toString(16)).slice(-o)+("0000000000"+i.toString(16)).slice(-o);return this.setPrivateKeyHex(s),this.setPublicKeyHex(a),{ecprvhex:s,ecpubhex:a}},this.signWithMessageHash=function(t){return this.signHex(t,this.prvKeyHex)},this.signHex=function(t,e){var n=new r(e,16),o=this.ecparams.n,s=new r(t.substring(0,this.ecparams.keylen/4),16);do{var a=this.getBigRandom(o),u=this.ecparams.G.multiply(a).getX().toBigInteger().mod(o)}while(u.compareTo(r.ZERO)<=0);var c=a.modInverse(o).multiply(s.add(n.multiply(u))).mod(o);return i.biRSSigToASN1Sig(u,c)},this.sign=function(t,e){var n=e,i=this.ecparams.n,o=r.fromByteArrayUnsigned(t);do{var s=this.getBigRandom(i),a=this.ecparams.G.multiply(s).getX().toBigInteger().mod(i)}while(a.compareTo(w.ZERO)<=0);var u=s.modInverse(i).multiply(o.add(n.multiply(a))).mod(i);return this.serializeSig(a,u)},this.verifyWithMessageHash=function(t,e){return this.verifyHex(t,e,this.pubKeyHex)},this.verifyHex=function(t,e,o){try{var s,a,u=i.parseSigHex(e);s=u.r,a=u.s;var c=n.decodeFromHex(this.ecparams.curve,o),h=new r(t.substring(0,this.ecparams.keylen/4),16);return this.verifyRaw(h,s,a,c)}catch(t){return!1}},this.verify=function(t,e,i){var o,s,a;if(Bitcoin.Util.isArray(e)){var u=this.parseSig(e);o=u.r,s=u.s}else{if("object"!==(void 0===e?"undefined":g(e))||!e.r||!e.s)throw"Invalid value for signature";o=e.r,s=e.s}if(i instanceof Ve)a=i;else{if(!Bitcoin.Util.isArray(i))throw"Invalid format for pubkey value, must be byte array or ECPointFp";a=n.decodeFrom(this.ecparams.curve,i)}var c=r.fromByteArrayUnsigned(t);return this.verifyRaw(c,o,s,a)},this.verifyRaw=function(t,e,n,i){var o=this.ecparams.n,s=this.ecparams.G;if(e.compareTo(r.ONE)<0||e.compareTo(o)>=0)return!1;if(n.compareTo(r.ONE)<0||n.compareTo(o)>=0)return!1;var a=n.modInverse(o),u=t.multiply(a).mod(o),c=e.multiply(a).mod(o);return s.multiply(u).add(i.multiply(c)).getX().toBigInteger().mod(o).equals(e)},this.serializeSig=function(t,e){var r=t.toByteArraySigned(),n=e.toByteArraySigned(),i=[];return i.push(2),i.push(r.length),(i=i.concat(r)).push(2),i.push(n.length),(i=i.concat(n)).unshift(i.length),i.unshift(48),i},this.parseSig=function(t){var e;if(48!=t[0])throw new Error("Signature not a valid DERSequence");if(2!=t[e=2])throw new Error("First element in signature must be a DERInteger");var n=t.slice(e+2,e+2+t[e+1]);if(2!=t[e+=2+t[e+1]])throw new Error("Second element in signature must be a DERInteger");var i=t.slice(e+2,e+2+t[e+1]);return e+=2+t[e+1],{r:r.fromByteArrayUnsigned(n),s:r.fromByteArrayUnsigned(i)}},this.parseSigCompact=function(t){if(65!==t.length)throw"Signature has the wrong length";var e=t[0]-27;if(e<0||e>7)throw"Invalid signature type";var n=this.ecparams.n;return{r:r.fromByteArrayUnsigned(t.slice(1,33)).mod(n),s:r.fromByteArrayUnsigned(t.slice(33,65)).mod(n),i:e}},this.readPKCS5PrvKeyHex=function(t){if(!1===c(t))throw new Error("not ASN.1 hex string");var e,r,n;try{e=u(t,0,["[0]",0],"06"),r=u(t,0,[1],"04");try{n=u(t,0,["[1]",0],"03")}catch(t){}}catch(t){throw new Error("malformed PKCS#1/5 plain ECC private key")}if(this.curveName=s(e),void 0===this.curveName)throw"unsupported curve name";this.setNamedCurve(this.curveName),this.setPublicKeyHex(n),this.setPrivateKeyHex(r),this.isPublic=!1},this.readPKCS8PrvKeyHex=function(t){if(!1===c(t))throw new e("not ASN.1 hex string");var r,n,i;try{u(t,0,[1,0],"06"),r=u(t,0,[1,1],"06"),n=u(t,0,[2,0,1],"04");try{i=u(t,0,[2,0,"[1]",0],"03")}catch(t){}}catch(t){throw new e("malformed PKCS#8 plain ECC private key")}if(this.curveName=s(r),void 0===this.curveName)throw new e("unsupported curve name");this.setNamedCurve(this.curveName),this.setPublicKeyHex(i),this.setPrivateKeyHex(n),this.isPublic=!1},this.readPKCS8PubKeyHex=function(t){if(!1===c(t))throw new e("not ASN.1 hex string");var r,n;try{u(t,0,[0,0],"06"),r=u(t,0,[0,1],"06"),n=u(t,0,[1],"03")}catch(t){throw new e("malformed PKCS#8 ECC public key")}if(this.curveName=s(r),null===this.curveName)throw new e("unsupported curve name");this.setNamedCurve(this.curveName),this.setPublicKeyHex(n)},this.readCertPubKeyHex=function(t,r){if(!1===c(t))throw new e("not ASN.1 hex string");var n,i;try{n=u(t,0,[0,5,0,1],"06"),i=u(t,0,[0,5,1],"03")}catch(t){throw new e("malformed X.509 certificate ECC public key")}if(this.curveName=s(n),null===this.curveName)throw new e("unsupported curve name");this.setNamedCurve(this.curveName),this.setPublicKeyHex(i)},void 0!==t&&void 0!==t.curve&&(this.curveName=t.curve),void 0===this.curveName&&(this.curveName="secp256r1"),this.setNamedCurve(this.curveName),void 0!==t&&(void 0!==t.prv&&this.setPrivateKeyHex(t.prv),void 0!==t.pub&&this.setPublicKeyHex(t.pub))},Sr.crypto.ECDSA.parseSigHex=function(t){var e=Sr.crypto.ECDSA.parseSigHexInHexRS(t);return{r:new w(e.r,16),s:new w(e.s,16)}},Sr.crypto.ECDSA.parseSigHexInHexRS=function(t){var e=Fr,r=e.getChildIdx,n=e.getV;if(e.checkStrictDER(t,0),"30"!=t.substr(0,2))throw new Error("signature is not a ASN.1 sequence");var i=r(t,0);if(2!=i.length)throw new Error("signature shall have two elements");var o=i[0],s=i[1];if("02"!=t.substr(o,2))throw new Error("1st item not ASN.1 integer");if("02"!=t.substr(s,2))throw new Error("2nd item not ASN.1 integer");return{r:n(t,o),s:n(t,s)}},Sr.crypto.ECDSA.asn1SigToConcatSig=function(t){var e=Sr.crypto.ECDSA.parseSigHexInHexRS(t),r=e.r,n=e.s;if("00"==r.substr(0,2)&&r.length%32==2&&(r=r.substr(2)),"00"==n.substr(0,2)&&n.length%32==2&&(n=n.substr(2)),r.length%32==30&&(r="00"+r),n.length%32==30&&(n="00"+n),r.length%32!=0)throw"unknown ECDSA sig r length error";if(n.length%32!=0)throw"unknown ECDSA sig s length error";return r+n},Sr.crypto.ECDSA.concatSigToASN1Sig=function(t){if(t.length/2*8%128!=0)throw"unknown ECDSA concatinated r-s sig  length error";var e=t.substr(0,t.length/2),r=t.substr(t.length/2);return Sr.crypto.ECDSA.hexRSSigToASN1Sig(e,r)},Sr.crypto.ECDSA.hexRSSigToASN1Sig=function(t,e){var r=new w(t,16),n=new w(e,16);return Sr.crypto.ECDSA.biRSSigToASN1Sig(r,n)},Sr.crypto.ECDSA.biRSSigToASN1Sig=function(t,e){var r=Sr.asn1,n=new r.DERInteger({bigint:t}),i=new r.DERInteger({bigint:e});return new r.DERSequence({array:[n,i]}).getEncodedHex()},Sr.crypto.ECDSA.getName=function(t){return"2b8104001f"===t?"secp192k1":"2a8648ce3d030107"===t?"secp256r1":"2b8104000a"===t?"secp256k1":"2b81040021"===t?"secp224r1":"2b81040022"===t?"secp384r1":-1!=="|secp256r1|NIST P-256|P-256|prime256v1|".indexOf(t)?"secp256r1":-1!=="|secp256k1|".indexOf(t)?"secp256k1":-1!=="|secp224r1|NIST P-224|P-224|".indexOf(t)?"secp224r1":-1!=="|secp384r1|NIST P-384|P-384|".indexOf(t)?"secp384r1":null},void 0!==Sr&&Sr||(e.KJUR=Sr={}),void 0!==Sr.crypto&&Sr.crypto||(Sr.crypto={}),Sr.crypto.ECParameterDB=new function(){var t={},e={};function r(t){return new w(t,16)}this.getByName=function(r){var n=r;if(void 0!==e[n]&&(n=e[r]),void 0!==t[n])return t[n];throw"unregistered EC curve name: "+n},this.regist=function(n,i,o,s,a,u,c,h,l,f,g,d){t[n]={};var p=r(o),v=r(s),y=r(a),m=r(u),_=r(c),S=new Ke(p,v,y),b=S.decodePointHex("04"+h+l);t[n].name=n,t[n].keylen=i,t[n].curve=S,t[n].G=b,t[n].n=m,t[n].h=_,t[n].oid=g,t[n].info=d;for(var w=0;w<f.length;w++)e[f[w]]=n}},Sr.crypto.ECParameterDB.regist("secp128r1",128,"FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF","FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC","E87579C11079F43DD824993C2CEE5ED3","FFFFFFFE0000000075A30D1B9038A115","1","161FF7528B899B2D0C28607CA52C5B86","CF5AC8395BAFEB13C02DA292DDED7A83",[],"","secp128r1 : SECG curve over a 128 bit prime field"),Sr.crypto.ECParameterDB.regist("secp160k1",160,"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73","0","7","0100000000000000000001B8FA16DFAB9ACA16B6B3","1","3B4C382CE37AA192A4019E763036F4F5DD4D7EBB","938CF935318FDCED6BC28286531733C3F03C4FEE",[],"","secp160k1 : SECG curve over a 160 bit prime field"),Sr.crypto.ECParameterDB.regist("secp160r1",160,"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF","FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC","1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45","0100000000000000000001F4C8F927AED3CA752257","1","4A96B5688EF573284664698968C38BB913CBFC82","23A628553168947D59DCC912042351377AC5FB32",[],"","secp160r1 : SECG curve over a 160 bit prime field"),Sr.crypto.ECParameterDB.regist("secp192k1",192,"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37","0","3","FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D","1","DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D","9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D",[]),Sr.crypto.ECParameterDB.regist("secp192r1",192,"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF","FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC","64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1","FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831","1","188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012","07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",[]),Sr.crypto.ECParameterDB.regist("secp224r1",224,"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001","FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE","B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4","FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D","1","B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21","BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",[]),Sr.crypto.ECParameterDB.regist("secp256k1",256,"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F","0","7","FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141","1","79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798","483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",[]),Sr.crypto.ECParameterDB.regist("secp256r1",256,"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF","FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC","5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B","FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551","1","6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296","4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",["NIST P-256","P-256","prime256v1"]),Sr.crypto.ECParameterDB.regist("secp384r1",384,"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF","FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC","B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF","FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973","1","AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7","3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",["NIST P-384","P-384"]),Sr.crypto.ECParameterDB.regist("secp521r1",521,"1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF","1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC","051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00","1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409","1","C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66","011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",["NIST P-521","P-521"]);var tn=function(){var t=function t(r,n,i){return e(v.AES,r,n,i)},e=function t(e,r,n,i){var o=v.enc.Hex.parse(r),s=v.enc.Hex.parse(n),a=v.enc.Hex.parse(i),u={};u.key=s,u.iv=a,u.ciphertext=o;var c=e.decrypt(u,s,{iv:a});return v.enc.Hex.stringify(c)},r=function t(e,r,i){return n(v.AES,e,r,i)},n=function t(e,r,n,i){var o=v.enc.Hex.parse(r),s=v.enc.Hex.parse(n),a=v.enc.Hex.parse(i),u=e.encrypt(o,s,{iv:a}),c=v.enc.Hex.parse(u.toString());return v.enc.Base64.stringify(c)},i={"AES-256-CBC":{proc:t,eproc:r,keylen:32,ivlen:16},"AES-192-CBC":{proc:t,eproc:r,keylen:24,ivlen:16},"AES-128-CBC":{proc:t,eproc:r,keylen:16,ivlen:16},"DES-EDE3-CBC":{proc:function t(r,n,i){return e(v.TripleDES,r,n,i)},eproc:function t(e,r,i){return n(v.TripleDES,e,r,i)},keylen:24,ivlen:8},"DES-CBC":{proc:function t(r,n,i){return e(v.DES,r,n,i)},eproc:function t(e,r,i){return n(v.DES,e,r,i)},keylen:8,ivlen:8}},o=function t(e){var r={},n=e.match(new RegExp("DEK-Info: ([^,]+),([0-9A-Fa-f]+)","m"));n&&(r.cipher=n[1],r.ivsalt=n[2]);var i=e.match(new RegExp("-----BEGIN ([A-Z]+) PRIVATE KEY-----"));i&&(r.type=i[1]);var o=-1,s=0;-1!=e.indexOf("\r\n\r\n")&&(o=e.indexOf("\r\n\r\n"),s=2),-1!=e.indexOf("\n\n")&&(o=e.indexOf("\n\n"),s=1);var a=e.indexOf("-----END");if(-1!=o&&-1!=a){var u=e.substring(o+2*s,a-s);u=u.replace(/\s+/g,""),r.data=u}return r},s=function t(e,r,n){for(var o=n.substring(0,16),s=v.enc.Hex.parse(o),a=v.enc.Utf8.parse(r),u=i[e].keylen+i[e].ivlen,c="",h=null;;){var l=v.algo.MD5.create();if(null!=h&&l.update(h),l.update(a),l.update(s),h=l.finalize(),(c+=v.enc.Hex.stringify(h)).length>=2*u)break}var f={};return f.keyhex=c.substr(0,2*i[e].keylen),f.ivhex=c.substr(2*i[e].keylen,2*i[e].ivlen),f},a=function t(e,r,n,o){var s=v.enc.Base64.parse(e),a=v.enc.Hex.stringify(s);return(0,i[r].proc)(a,n,o)};return{version:"1.0.0",parsePKCS5PEM:function t(e){return o(e)},getKeyAndUnusedIvByPasscodeAndIvsalt:function t(e,r,n){return s(e,r,n)},decryptKeyB64:function t(e,r,n,i){return a(e,r,n,i)},getDecryptedKeyHex:function t(e,r){var n=o(e),i=(n.type,n.cipher),u=n.ivsalt,c=n.data,h=s(i,r,u).keyhex;return a(c,i,h,u)},getEncryptedPKCS5PEMFromPrvKeyHex:function t(e,r,n,o,a){var u="";if(void 0!==o&&null!=o||(o="AES-256-CBC"),void 0===i[o])throw new Error("KEYUTIL unsupported algorithm: "+o);void 0!==a&&null!=a||(a=function t(e){var r=v.lib.WordArray.random(e);return v.enc.Hex.stringify(r)}(i[o].ivlen).toUpperCase());var c=function t(e,r,n,o){return(0,i[r].eproc)(e,n,o)}(r,o,s(o,n,a).keyhex,a);u="-----BEGIN "+e+" PRIVATE KEY-----\r\n";return u+="Proc-Type: 4,ENCRYPTED\r\n",u+="DEK-Info: "+o+","+a+"\r\n",u+="\r\n",u+=c.replace(/(.{64})/g,"$1\r\n"),u+="\r\n-----END "+e+" PRIVATE KEY-----\r\n"},parseHexOfEncryptedPKCS8:function t(e){var r=Fr,n=r.getChildIdx,i=r.getV,o={},s=n(e,0);if(2!=s.length)throw new Error("malformed format: SEQUENCE(0).items != 2: "+s.length);o.ciphertext=i(e,s[1]);var a=n(e,s[0]);if(2!=a.length)throw new Error("malformed format: SEQUENCE(0.0).items != 2: "+a.length);if("2a864886f70d01050d"!=i(e,a[0]))throw new Error("this only supports pkcs5PBES2");var u=n(e,a[1]);if(2!=a.length)throw new Error("malformed format: SEQUENCE(0.0.1).items != 2: "+u.length);var c=n(e,u[1]);if(2!=c.length)throw new Error("malformed format: SEQUENCE(0.0.1.1).items != 2: "+c.length);if("2a864886f70d0307"!=i(e,c[0]))throw"this only supports TripleDES";o.encryptionSchemeAlg="TripleDES",o.encryptionSchemeIV=i(e,c[1]);var h=n(e,u[0]);if(2!=h.length)throw new Error("malformed format: SEQUENCE(0.0.1.0).items != 2: "+h.length);if("2a864886f70d01050c"!=i(e,h[0]))throw new Error("this only supports pkcs5PBKDF2");var l=n(e,h[1]);if(l.length<2)throw new Error("malformed format: SEQUENCE(0.0.1.0.1).items < 2: "+l.length);o.pbkdf2Salt=i(e,l[0]);var f=i(e,l[1]);try{o.pbkdf2Iter=parseInt(f,16)}catch(t){throw new Error("malformed format pbkdf2Iter: "+f)}return o},getPBKDF2KeyHexFromParam:function t(e,r){var n=v.enc.Hex.parse(e.pbkdf2Salt),i=e.pbkdf2Iter,o=v.PBKDF2(r,n,{keySize:6,iterations:i});return v.enc.Hex.stringify(o)},_getPlainPKCS8HexFromEncryptedPKCS8PEM:function t(e,r){var n=Mr(e,"ENCRYPTED PRIVATE KEY"),i=this.parseHexOfEncryptedPKCS8(n),o=tn.getPBKDF2KeyHexFromParam(i,r),s={};s.ciphertext=v.enc.Hex.parse(i.ciphertext);var a=v.enc.Hex.parse(o),u=v.enc.Hex.parse(i.encryptionSchemeIV),c=v.TripleDES.decrypt(s,a,{iv:u});return v.enc.Hex.stringify(c)},getKeyFromEncryptedPKCS8PEM:function t(e,r){var n=this._getPlainPKCS8HexFromEncryptedPKCS8PEM(e,r);return this.getKeyFromPlainPrivatePKCS8Hex(n)},parsePlainPrivatePKCS8Hex:function t(e){var r=Fr,n=r.getChildIdx,i=r.getV,o={algparam:null};if("30"!=e.substr(0,2))throw new Error("malformed plain PKCS8 private key(code:001)");var s=n(e,0);if(s.length<3)throw new Error("malformed plain PKCS8 private key(code:002)");if("30"!=e.substr(s[1],2))throw new Error("malformed PKCS8 private key(code:003)");var a=n(e,s[1]);if(2!=a.length)throw new Error("malformed PKCS8 private key(code:004)");if("06"!=e.substr(a[0],2))throw new Error("malformed PKCS8 private key(code:005)");if(o.algoid=i(e,a[0]),"06"==e.substr(a[1],2)&&(o.algparam=i(e,a[1])),"04"!=e.substr(s[2],2))throw new Error("malformed PKCS8 private key(code:006)");return o.keyidx=r.getVidx(e,s[2]),o},getKeyFromPlainPrivatePKCS8PEM:function t(e){var r=Mr(e,"PRIVATE KEY");return this.getKeyFromPlainPrivatePKCS8Hex(r)},getKeyFromPlainPrivatePKCS8Hex:function t(e){var r,n=this.parsePlainPrivatePKCS8Hex(e);if("2a864886f70d010101"==n.algoid)r=new Me;else if("2a8648ce380401"==n.algoid)r=new Sr.crypto.DSA;else{if("2a8648ce3d0201"!=n.algoid)throw new Error("unsupported private key algorithm");r=new Sr.crypto.ECDSA}return r.readPKCS8PrvKeyHex(e),r},_getKeyFromPublicPKCS8Hex:function t(e){var r,n=Fr.getVbyList(e,0,[0,0],"06");if("2a864886f70d010101"===n)r=new Me;else if("2a8648ce380401"===n)r=new Sr.crypto.DSA;else{if("2a8648ce3d0201"!==n)throw new Error("unsupported PKCS#8 public key hex");r=new Sr.crypto.ECDSA}return r.readPKCS8PubKeyHex(e),r},parsePublicRawRSAKeyHex:function t(e){var r=Fr,n=r.getChildIdx,i=r.getV,o={};if("30"!=e.substr(0,2))throw new Error("malformed RSA key(code:001)");var s=n(e,0);if(2!=s.length)throw new Error("malformed RSA key(code:002)");if("02"!=e.substr(s[0],2))throw new Error("malformed RSA key(code:003)");if(o.n=i(e,s[0]),"02"!=e.substr(s[1],2))throw new Error("malformed RSA key(code:004)");return o.e=i(e,s[1]),o},parsePublicPKCS8Hex:function t(e){var r=Fr,n=r.getChildIdx,i=r.getV,o={algparam:null},s=n(e,0);if(2!=s.length)throw new Error("outer DERSequence shall have 2 elements: "+s.length);var a=s[0];if("30"!=e.substr(a,2))throw new Error("malformed PKCS8 public key(code:001)");var u=n(e,a);if(2!=u.length)throw new Error("malformed PKCS8 public key(code:002)");if("06"!=e.substr(u[0],2))throw new Error("malformed PKCS8 public key(code:003)");if(o.algoid=i(e,u[0]),"06"==e.substr(u[1],2)?o.algparam=i(e,u[1]):"30"==e.substr(u[1],2)&&(o.algparam={},o.algparam.p=r.getVbyList(e,u[1],[0],"02"),o.algparam.q=r.getVbyList(e,u[1],[1],"02"),o.algparam.g=r.getVbyList(e,u[1],[2],"02")),"03"!=e.substr(s[1],2))throw new Error("malformed PKCS8 public key(code:004)");return o.key=i(e,s[1]).substr(2),o}}}();tn.getKey=function(t,e,r){var n=(v=Fr).getChildIdx,i=(v.getV,v.getVbyList),o=Sr.crypto,s=o.ECDSA,a=o.DSA,u=Me,c=Mr,h=tn;if(void 0!==u&&t instanceof u)return t;if(void 0!==s&&t instanceof s)return t;if(void 0!==a&&t instanceof a)return t;if(void 0!==t.curve&&void 0!==t.xy&&void 0===t.d)return new s({pub:t.xy,curve:t.curve});if(void 0!==t.curve&&void 0!==t.d)return new s({prv:t.d,curve:t.curve});if(void 0===t.kty&&void 0!==t.n&&void 0!==t.e&&void 0===t.d)return(P=new u).setPublic(t.n,t.e),P;if(void 0===t.kty&&void 0!==t.n&&void 0!==t.e&&void 0!==t.d&&void 0!==t.p&&void 0!==t.q&&void 0!==t.dp&&void 0!==t.dq&&void 0!==t.co&&void 0===t.qi)return(P=new u).setPrivateEx(t.n,t.e,t.d,t.p,t.q,t.dp,t.dq,t.co),P;if(void 0===t.kty&&void 0!==t.n&&void 0!==t.e&&void 0!==t.d&&void 0===t.p)return(P=new u).setPrivate(t.n,t.e,t.d),P;if(void 0!==t.p&&void 0!==t.q&&void 0!==t.g&&void 0!==t.y&&void 0===t.x)return(P=new a).setPublic(t.p,t.q,t.g,t.y),P;if(void 0!==t.p&&void 0!==t.q&&void 0!==t.g&&void 0!==t.y&&void 0!==t.x)return(P=new a).setPrivate(t.p,t.q,t.g,t.y,t.x),P;if("RSA"===t.kty&&void 0!==t.n&&void 0!==t.e&&void 0===t.d)return(P=new u).setPublic(Rr(t.n),Rr(t.e)),P;if("RSA"===t.kty&&void 0!==t.n&&void 0!==t.e&&void 0!==t.d&&void 0!==t.p&&void 0!==t.q&&void 0!==t.dp&&void 0!==t.dq&&void 0!==t.qi)return(P=new u).setPrivateEx(Rr(t.n),Rr(t.e),Rr(t.d),Rr(t.p),Rr(t.q),Rr(t.dp),Rr(t.dq),Rr(t.qi)),P;if("RSA"===t.kty&&void 0!==t.n&&void 0!==t.e&&void 0!==t.d)return(P=new u).setPrivate(Rr(t.n),Rr(t.e),Rr(t.d)),P;if("EC"===t.kty&&void 0!==t.crv&&void 0!==t.x&&void 0!==t.y&&void 0===t.d){var l=(k=new s({curve:t.crv})).ecparams.keylen/4,f="04"+("0000000000"+Rr(t.x)).slice(-l)+("0000000000"+Rr(t.y)).slice(-l);return k.setPublicKeyHex(f),k}if("EC"===t.kty&&void 0!==t.crv&&void 0!==t.x&&void 0!==t.y&&void 0!==t.d){l=(k=new s({curve:t.crv})).ecparams.keylen/4,f="04"+("0000000000"+Rr(t.x)).slice(-l)+("0000000000"+Rr(t.y)).slice(-l);var g=("0000000000"+Rr(t.d)).slice(-l);return k.setPublicKeyHex(f),k.setPrivateKeyHex(g),k}if("pkcs5prv"===r){var d,p=t,v=Fr;if(9===(d=n(p,0)).length)(P=new u).readPKCS5PrvKeyHex(p);else if(6===d.length)(P=new a).readPKCS5PrvKeyHex(p);else{if(!(d.length>2&&"04"===p.substr(d[1],2)))throw new Error("unsupported PKCS#1/5 hexadecimal key");(P=new s).readPKCS5PrvKeyHex(p)}return P}if("pkcs8prv"===r)return P=h.getKeyFromPlainPrivatePKCS8Hex(t);if("pkcs8pub"===r)return h._getKeyFromPublicPKCS8Hex(t);if("x509pub"===r)return on.getPublicKeyFromCertHex(t);if(-1!=t.indexOf("-END CERTIFICATE-",0)||-1!=t.indexOf("-END X509 CERTIFICATE-",0)||-1!=t.indexOf("-END TRUSTED CERTIFICATE-",0))return on.getPublicKeyFromCertPEM(t);if(-1!=t.indexOf("-END PUBLIC KEY-")){var y=Mr(t,"PUBLIC KEY");return h._getKeyFromPublicPKCS8Hex(y)}if(-1!=t.indexOf("-END RSA PRIVATE KEY-")&&-1==t.indexOf("4,ENCRYPTED")){var m=c(t,"RSA PRIVATE KEY");return h.getKey(m,null,"pkcs5prv")}if(-1!=t.indexOf("-END DSA PRIVATE KEY-")&&-1==t.indexOf("4,ENCRYPTED")){var _=i(R=c(t,"DSA PRIVATE KEY"),0,[1],"02"),S=i(R,0,[2],"02"),b=i(R,0,[3],"02"),F=i(R,0,[4],"02"),E=i(R,0,[5],"02");return(P=new a).setPrivate(new w(_,16),new w(S,16),new w(b,16),new w(F,16),new w(E,16)),P}if(-1!=t.indexOf("-END EC PRIVATE KEY-")&&-1==t.indexOf("4,ENCRYPTED")){m=c(t,"EC PRIVATE KEY");return h.getKey(m,null,"pkcs5prv")}if(-1!=t.indexOf("-END PRIVATE KEY-"))return h.getKeyFromPlainPrivatePKCS8PEM(t);if(-1!=t.indexOf("-END RSA PRIVATE KEY-")&&-1!=t.indexOf("4,ENCRYPTED")){var x=h.getDecryptedKeyHex(t,e),A=new Me;return A.readPKCS5PrvKeyHex(x),A}if(-1!=t.indexOf("-END EC PRIVATE KEY-")&&-1!=t.indexOf("4,ENCRYPTED")){var k,P=i(R=h.getDecryptedKeyHex(t,e),0,[1],"04"),C=i(R,0,[2,0],"06"),T=i(R,0,[3,0],"03").substr(2);if(void 0===Sr.crypto.OID.oidhex2name[C])throw new Error("undefined OID(hex) in KJUR.crypto.OID: "+C);return(k=new s({curve:Sr.crypto.OID.oidhex2name[C]})).setPublicKeyHex(T),k.setPrivateKeyHex(P),k.isPublic=!1,k}if(-1!=t.indexOf("-END DSA PRIVATE KEY-")&&-1!=t.indexOf("4,ENCRYPTED")){var R;_=i(R=h.getDecryptedKeyHex(t,e),0,[1],"02"),S=i(R,0,[2],"02"),b=i(R,0,[3],"02"),F=i(R,0,[4],"02"),E=i(R,0,[5],"02");return(P=new a).setPrivate(new w(_,16),new w(S,16),new w(b,16),new w(F,16),new w(E,16)),P}if(-1!=t.indexOf("-END ENCRYPTED PRIVATE KEY-"))return h.getKeyFromEncryptedPKCS8PEM(t,e);throw new Error("not supported argument")},tn.generateKeypair=function(t,e){if("RSA"==t){var r=e;(s=new Me).generate(r,"10001"),s.isPrivate=!0,s.isPublic=!0;var n=new Me,i=s.n.toString(16),o=s.e.toString(16);return n.setPublic(i,o),n.isPrivate=!1,n.isPublic=!0,(a={}).prvKeyObj=s,a.pubKeyObj=n,a}if("EC"==t){var s,a,u=e,c=new Sr.crypto.ECDSA({curve:u}).generateKeyPairHex();return(s=new Sr.crypto.ECDSA({curve:u})).setPublicKeyHex(c.ecpubhex),s.setPrivateKeyHex(c.ecprvhex),s.isPrivate=!0,s.isPublic=!1,(n=new Sr.crypto.ECDSA({curve:u})).setPublicKeyHex(c.ecpubhex),n.isPrivate=!1,n.isPublic=!0,(a={}).prvKeyObj=s,a.pubKeyObj=n,a}throw new Error("unknown algorithm: "+t)},tn.getPEM=function(t,e,r,n,i,o){var s=Sr,a=s.asn1,u=a.DERObjectIdentifier,c=a.DERInteger,h=a.ASN1Util.newObject,l=a.x509.SubjectPublicKeyInfo,f=s.crypto,g=f.DSA,d=f.ECDSA,p=Me;function y(t){return h({seq:[{int:0},{int:{bigint:t.n}},{int:t.e},{int:{bigint:t.d}},{int:{bigint:t.p}},{int:{bigint:t.q}},{int:{bigint:t.dmp1}},{int:{bigint:t.dmq1}},{int:{bigint:t.coeff}}]})}function m(t){return h({seq:[{int:1},{octstr:{hex:t.prvKeyHex}},{tag:["a0",!0,{oid:{name:t.curveName}}]},{tag:["a1",!0,{bitstr:{hex:"00"+t.pubKeyHex}}]}]})}function _(t){return h({seq:[{int:0},{int:{bigint:t.p}},{int:{bigint:t.q}},{int:{bigint:t.g}},{int:{bigint:t.y}},{int:{bigint:t.x}}]})}if((void 0!==p&&t instanceof p||void 0!==g&&t instanceof g||void 0!==d&&t instanceof d)&&1==t.isPublic&&(void 0===e||"PKCS8PUB"==e))return jr(F=new l(t).getEncodedHex(),"PUBLIC KEY");if("PKCS1PRV"==e&&void 0!==p&&t instanceof p&&(void 0===r||null==r)&&1==t.isPrivate)return jr(F=y(t).getEncodedHex(),"RSA PRIVATE KEY");if("PKCS1PRV"==e&&void 0!==d&&t instanceof d&&(void 0===r||null==r)&&1==t.isPrivate){var S=new u({name:t.curveName}).getEncodedHex(),b=m(t).getEncodedHex(),w="";return w+=jr(S,"EC PARAMETERS"),w+=jr(b,"EC PRIVATE KEY")}if("PKCS1PRV"==e&&void 0!==g&&t instanceof g&&(void 0===r||null==r)&&1==t.isPrivate)return jr(F=_(t).getEncodedHex(),"DSA PRIVATE KEY");if("PKCS5PRV"==e&&void 0!==p&&t instanceof p&&void 0!==r&&null!=r&&1==t.isPrivate){var F=y(t).getEncodedHex();return void 0===n&&(n="DES-EDE3-CBC"),this.getEncryptedPKCS5PEMFromPrvKeyHex("RSA",F,r,n,o)}if("PKCS5PRV"==e&&void 0!==d&&t instanceof d&&void 0!==r&&null!=r&&1==t.isPrivate){F=m(t).getEncodedHex();return void 0===n&&(n="DES-EDE3-CBC"),this.getEncryptedPKCS5PEMFromPrvKeyHex("EC",F,r,n,o)}if("PKCS5PRV"==e&&void 0!==g&&t instanceof g&&void 0!==r&&null!=r&&1==t.isPrivate){F=_(t).getEncodedHex();return void 0===n&&(n="DES-EDE3-CBC"),this.getEncryptedPKCS5PEMFromPrvKeyHex("DSA",F,r,n,o)}var E=function t(e,r){var n=x(e,r);return new h({seq:[{seq:[{oid:{name:"pkcs5PBES2"}},{seq:[{seq:[{oid:{name:"pkcs5PBKDF2"}},{seq:[{octstr:{hex:n.pbkdf2Salt}},{int:n.pbkdf2Iter}]}]},{seq:[{oid:{name:"des-EDE3-CBC"}},{octstr:{hex:n.encryptionSchemeIV}}]}]}]},{octstr:{hex:n.ciphertext}}]}).getEncodedHex()},x=function t(e,r){var n=v.lib.WordArray.random(8),i=v.lib.WordArray.random(8),o=v.PBKDF2(r,n,{keySize:6,iterations:100}),s=v.enc.Hex.parse(e),a=v.TripleDES.encrypt(s,o,{iv:i})+"",u={};return u.ciphertext=a,u.pbkdf2Salt=v.enc.Hex.stringify(n),u.pbkdf2Iter=100,u.encryptionSchemeAlg="DES-EDE3-CBC",u.encryptionSchemeIV=v.enc.Hex.stringify(i),u};if("PKCS8PRV"==e&&null!=p&&t instanceof p&&1==t.isPrivate){var A=y(t).getEncodedHex();F=h({seq:[{int:0},{seq:[{oid:{name:"rsaEncryption"}},{null:!0}]},{octstr:{hex:A}}]}).getEncodedHex();return void 0===r||null==r?jr(F,"PRIVATE KEY"):jr(b=E(F,r),"ENCRYPTED PRIVATE KEY")}if("PKCS8PRV"==e&&void 0!==d&&t instanceof d&&1==t.isPrivate){A=new h({seq:[{int:1},{octstr:{hex:t.prvKeyHex}},{tag:["a1",!0,{bitstr:{hex:"00"+t.pubKeyHex}}]}]}).getEncodedHex(),F=h({seq:[{int:0},{seq:[{oid:{name:"ecPublicKey"}},{oid:{name:t.curveName}}]},{octstr:{hex:A}}]}).getEncodedHex();return void 0===r||null==r?jr(F,"PRIVATE KEY"):jr(b=E(F,r),"ENCRYPTED PRIVATE KEY")}if("PKCS8PRV"==e&&void 0!==g&&t instanceof g&&1==t.isPrivate){A=new c({bigint:t.x}).getEncodedHex(),F=h({seq:[{int:0},{seq:[{oid:{name:"dsa"}},{seq:[{int:{bigint:t.p}},{int:{bigint:t.q}},{int:{bigint:t.g}}]}]},{octstr:{hex:A}}]}).getEncodedHex();return void 0===r||null==r?jr(F,"PRIVATE KEY"):jr(b=E(F,r),"ENCRYPTED PRIVATE KEY")}throw new Error("unsupported object nor format")},tn.getKeyFromCSRPEM=function(t){var e=Mr(t,"CERTIFICATE REQUEST");return tn.getKeyFromCSRHex(e)},tn.getKeyFromCSRHex=function(t){var e=tn.parseCSRHex(t);return tn.getKey(e.p8pubkeyhex,null,"pkcs8pub")},tn.parseCSRHex=function(t){var e=Fr,r=e.getChildIdx,n=e.getTLV,i={},o=t;if("30"!=o.substr(0,2))throw new Error("malformed CSR(code:001)");var s=r(o,0);if(s.length<1)throw new Error("malformed CSR(code:002)");if("30"!=o.substr(s[0],2))throw new Error("malformed CSR(code:003)");var a=r(o,s[0]);if(a.length<3)throw new Error("malformed CSR(code:004)");return i.p8pubkeyhex=n(o,a[2]),i},tn.getKeyID=function(t){var e=tn,r=Fr;"string"==typeof t&&-1!=t.indexOf("BEGIN ")&&(t=e.getKey(t));var n=Mr(e.getPEM(t)),i=r.getIdxbyList(n,0,[1]),o=r.getV(n,i).substring(2);return Sr.crypto.Util.hashHex(o,"sha1")},tn.getJWKFromKey=function(t){var e={};if(t instanceof Me&&t.isPrivate)return e.kty="RSA",e.n=Tr(t.n.toString(16)),e.e=Tr(t.e.toString(16)),e.d=Tr(t.d.toString(16)),e.p=Tr(t.p.toString(16)),e.q=Tr(t.q.toString(16)),e.dp=Tr(t.dmp1.toString(16)),e.dq=Tr(t.dmq1.toString(16)),e.qi=Tr(t.coeff.toString(16)),e;if(t instanceof Me&&t.isPublic)return e.kty="RSA",e.n=Tr(t.n.toString(16)),e.e=Tr(t.e.toString(16)),e;if(t instanceof Sr.crypto.ECDSA&&t.isPrivate){if("P-256"!==(n=t.getShortNISTPCurveName())&&"P-384"!==n)throw new Error("unsupported curve name for JWT: "+n);var r=t.getPublicKeyXYHex();return e.kty="EC",e.crv=n,e.x=Tr(r.x),e.y=Tr(r.y),e.d=Tr(t.prvKeyHex),e}if(t instanceof Sr.crypto.ECDSA&&t.isPublic){var n;if("P-256"!==(n=t.getShortNISTPCurveName())&&"P-384"!==n)throw new Error("unsupported curve name for JWT: "+n);r=t.getPublicKeyXYHex();return e.kty="EC",e.crv=n,e.x=Tr(r.x),e.y=Tr(r.y),e}throw new Error("not supported key object")},Me.getPosArrayOfChildrenFromHex=function(t){return Fr.getChildIdx(t,0)},Me.getHexValueArrayOfChildrenFromHex=function(t){var e,r=Fr.getV,n=r(t,(e=Me.getPosArrayOfChildrenFromHex(t))[0]),i=r(t,e[1]),o=r(t,e[2]),s=r(t,e[3]),a=r(t,e[4]),u=r(t,e[5]),c=r(t,e[6]),h=r(t,e[7]),l=r(t,e[8]);return(e=new Array).push(n,i,o,s,a,u,c,h,l),e},Me.prototype.readPrivateKeyFromPEMString=function(t){var e=Mr(t),r=Me.getHexValueArrayOfChildrenFromHex(e);this.setPrivateEx(r[1],r[2],r[3],r[4],r[5],r[6],r[7],r[8])},Me.prototype.readPKCS5PrvKeyHex=function(t){var e=Me.getHexValueArrayOfChildrenFromHex(t);this.setPrivateEx(e[1],e[2],e[3],e[4],e[5],e[6],e[7],e[8])},Me.prototype.readPKCS8PrvKeyHex=function(t){var e,r,n,i,o,s,a,u,c=Fr,h=c.getVbyListEx;if(!1===c.isASN1HEX(t))throw new Error("not ASN.1 hex string");try{e=h(t,0,[2,0,1],"02"),r=h(t,0,[2,0,2],"02"),n=h(t,0,[2,0,3],"02"),i=h(t,0,[2,0,4],"02"),o=h(t,0,[2,0,5],"02"),s=h(t,0,[2,0,6],"02"),a=h(t,0,[2,0,7],"02"),u=h(t,0,[2,0,8],"02")}catch(t){throw new Error("malformed PKCS#8 plain RSA private key")}this.setPrivateEx(e,r,n,i,o,s,a,u)},Me.prototype.readPKCS5PubKeyHex=function(t){var e=Fr,r=e.getV;if(!1===e.isASN1HEX(t))throw new Error("keyHex is not ASN.1 hex string");var n=e.getChildIdx(t,0);if(2!==n.length||"02"!==t.substr(n[0],2)||"02"!==t.substr(n[1],2))throw new Error("wrong hex for PKCS#5 public key");var i=r(t,n[0]),o=r(t,n[1]);this.setPublic(i,o)},Me.prototype.readPKCS8PubKeyHex=function(t){var e=Fr;if(!1===e.isASN1HEX(t))throw new Error("not ASN.1 hex string");if("06092a864886f70d010101"!==e.getTLVbyListEx(t,0,[0,0]))throw new Error("not PKCS8 RSA public key");var r=e.getTLVbyListEx(t,0,[1,0]);this.readPKCS5PubKeyHex(r)},Me.prototype.readCertPubKeyHex=function(t,e){var r,n;(r=new on).readCertHex(t),n=r.getPublicKeyHex(),this.readPKCS8PubKeyHex(n)};new RegExp("[^0-9a-f]","gi");function en(t,e){for(var r="",n=e/4-t.length,i=0;i<n;i++)r+="0";return r+t}function rn(t,e,r){for(var n="",i=0;n.length<e;)n+=Lr(r(Nr(t+String.fromCharCode.apply(String,[(4278190080&i)>>24,(16711680&i)>>16,(65280&i)>>8,255&i])))),i+=1;return n}function nn(t){for(var e in Sr.crypto.Util.DIGESTINFOHEAD){var r=Sr.crypto.Util.DIGESTINFOHEAD[e],n=r.length;if(t.substring(0,n)==r)return[e,t.substring(n)]}return[]}function on(t){var e,r=Fr,n=r.getChildIdx,i=r.getV,o=r.getTLV,s=r.getVbyList,a=r.getVbyListEx,u=r.getTLVbyList,c=r.getTLVbyListEx,h=r.getIdxbyList,l=r.getIdxbyListEx,f=r.getVidx,g=r.getInt,d=r.oidname,p=r.hextooidstr,v=Mr;try{e=Sr.asn1.x509.AlgorithmIdentifier.PSSNAME2ASN1TLV}catch(t){}this.HEX2STAG={"0c":"utf8",13:"prn",16:"ia5","1a":"vis","1e":"bmp"},this.hex=null,this.version=0,this.foffset=0,this.aExtInfo=null,this.getVersion=function(){if(null===this.hex||0!==this.version)return this.version;var t=u(this.hex,0,[0,0]);if("a0"==t.substr(0,2)){var e=u(t,0,[0]),r=g(e,0);if(r<0||2<r)throw new Error("malformed version field");return this.version=r+1,this.version}return this.version=1,this.foffset=-1,1},this.getSerialNumberHex=function(){return a(this.hex,0,[0,0],"02")},this.getSignatureAlgorithmField=function(){var t=c(this.hex,0,[0,1]);return this.getAlgorithmIdentifierName(t)},this.getAlgorithmIdentifierName=function(t){for(var r in e)if(t===e[r])return r;return d(a(t,0,[0],"06"))},this.getIssuer=function(){return this.getX500Name(this.getIssuerHex())},this.getIssuerHex=function(){return u(this.hex,0,[0,3+this.foffset],"30")},this.getIssuerString=function(){return this.getIssuer().str},this.getSubject=function(){return this.getX500Name(this.getSubjectHex())},this.getSubjectHex=function(){return u(this.hex,0,[0,5+this.foffset],"30")},this.getSubjectString=function(){return this.getSubject().str},this.getNotBefore=function(){var t=s(this.hex,0,[0,4+this.foffset,0]);return t=t.replace(/(..)/g,"%$1"),t=decodeURIComponent(t)},this.getNotAfter=function(){var t=s(this.hex,0,[0,4+this.foffset,1]);return t=t.replace(/(..)/g,"%$1"),t=decodeURIComponent(t)},this.getPublicKeyHex=function(){return r.getTLVbyList(this.hex,0,[0,6+this.foffset],"30")},this.getPublicKeyIdx=function(){return h(this.hex,0,[0,6+this.foffset],"30")},this.getPublicKeyContentIdx=function(){var t=this.getPublicKeyIdx();return h(this.hex,t,[1,0],"30")},this.getPublicKey=function(){return tn.getKey(this.getPublicKeyHex(),null,"pkcs8pub")},this.getSignatureAlgorithmName=function(){var t=u(this.hex,0,[1],"30");return this.getAlgorithmIdentifierName(t)},this.getSignatureValueHex=function(){return s(this.hex,0,[2],"03",!0)},this.verifySignature=function(t){var e=this.getSignatureAlgorithmField(),r=this.getSignatureValueHex(),n=u(this.hex,0,[0],"30"),i=new Sr.crypto.Signature({alg:e});return i.init(t),i.updateHex(n),i.verify(r)},this.parseExt=function(t){var e,o,a;if(void 0===t){if(a=this.hex,3!==this.version)return-1;e=h(a,0,[0,7,0],"30"),o=n(a,e)}else{a=Mr(t);var u=h(a,0,[0,3,0,0],"06");if("2a864886f70d01090e"!=i(a,u))return void(this.aExtInfo=new Array);e=h(a,0,[0,3,0,1,0],"30"),o=n(a,e),this.hex=a}this.aExtInfo=new Array;for(var c=0;c<o.length;c++){var l={critical:!1},g=0;3===n(a,o[c]).length&&(l.critical=!0,g=1),l.oid=r.hextooidstr(s(a,o[c],[0],"06"));var d=h(a,o[c],[1+g]);l.vidx=f(a,d),this.aExtInfo.push(l)}},this.getExtInfo=function(t){var e=this.aExtInfo,r=t;if(t.match(/^[0-9.]+$/)||(r=Sr.asn1.x509.OID.name2oid(t)),""!==r)for(var n=0;n<e.length;n++)if(e[n].oid===r)return e[n]},this.getExtBasicConstraints=function(t,e){if(void 0===t&&void 0===e){var r=this.getExtInfo("basicConstraints");if(void 0===r)return;t=o(this.hex,r.vidx),e=r.critical}var n={extname:"basicConstraints"};if(e&&(n.critical=!0),"3000"===t)return n;if("30030101ff"===t)return n.cA=!0,n;if("30060101ff02"===t.substr(0,12)){var s=i(t,10),a=parseInt(s,16);return n.cA=!0,n.pathLen=a,n}throw new Error("hExtV parse error: "+t)},this.getExtKeyUsage=function(t,e){if(void 0===t&&void 0===e){var r=this.getExtInfo("keyUsage");if(void 0===r)return;t=o(this.hex,r.vidx),e=r.critical}var n={extname:"keyUsage"};return e&&(n.critical=!0),n.names=this.getExtKeyUsageString(t).split(","),n},this.getExtKeyUsageBin=function(t){if(void 0===t){var e=this.getExtInfo("keyUsage");if(void 0===e)return"";t=o(this.hex,e.vidx)}if(8!=t.length&&10!=t.length)throw new Error("malformed key usage value: "+t);var r="000000000000000"+parseInt(t.substr(6),16).toString(2);return 8==t.length&&(r=r.slice(-8)),10==t.length&&(r=r.slice(-16)),""==(r=r.replace(/0+$/,""))&&(r="0"),r},this.getExtKeyUsageString=function(t){for(var e=this.getExtKeyUsageBin(t),r=new Array,n=0;n<e.length;n++)"1"==e.substr(n,1)&&r.push(on.KEYUSAGE_NAME[n]);return r.join(",")},this.getExtSubjectKeyIdentifier=function(t,e){if(void 0===t&&void 0===e){var r=this.getExtInfo("subjectKeyIdentifier");if(void 0===r)return;t=o(this.hex,r.vidx),e=r.critical}var n={extname:"subjectKeyIdentifier"};e&&(n.critical=!0);var s=i(t,0);return n.kid={hex:s},n},this.getExtAuthorityKeyIdentifier=function(t,e){if(void 0===t&&void 0===e){var r=this.getExtInfo("authorityKeyIdentifier");if(void 0===r)return;t=o(this.hex,r.vidx),e=r.critical}var s={extname:"authorityKeyIdentifier"};e&&(s.critical=!0);for(var a=n(t,0),u=0;u<a.length;u++){var c=t.substr(a[u],2);if("80"===c&&(s.kid={hex:i(t,a[u])}),"a1"===c){var h=o(t,a[u]),l=this.getGeneralNames(h);s.issuer=l[0].dn}"82"===c&&(s.sn={hex:i(t,a[u])})}return s},this.getExtExtKeyUsage=function(t,e){if(void 0===t&&void 0===e){var r=this.getExtInfo("extKeyUsage");if(void 0===r)return;t=o(this.hex,r.vidx),e=r.critical}var s={extname:"extKeyUsage",array:[]};e&&(s.critical=!0);for(var a=n(t,0),u=0;u<a.length;u++)s.array.push(d(i(t,a[u])));return s},this.getExtExtKeyUsageName=function(){var t=this.getExtInfo("extKeyUsage");if(void 0===t)return t;var e=new Array,r=o(this.hex,t.vidx);if(""===r)return e;for(var s=n(r,0),a=0;a<s.length;a++)e.push(d(i(r,s[a])));return e},this.getExtSubjectAltName=function(t,e){if(void 0===t&&void 0===e){var r=this.getExtInfo("subjectAltName");if(void 0===r)return;t=o(this.hex,r.vidx),e=r.critical}var n={extname:"subjectAltName",array:[]};return e&&(n.critical=!0),n.array=this.getGeneralNames(t),n},this.getExtIssuerAltName=function(t,e){if(void 0===t&&void 0===e){var r=this.getExtInfo("issuerAltName");if(void 0===r)return;t=o(this.hex,r.vidx),e=r.critical}var n={extname:"issuerAltName",array:[]};return e&&(n.critical=!0),n.array=this.getGeneralNames(t),n},this.getGeneralNames=function(t){for(var e=n(t,0),r=[],i=0;i<e.length;i++){var s=this.getGeneralName(o(t,e[i]));void 0!==s&&r.push(s)}return r},this.getGeneralName=function(t){var e=t.substr(0,2),r=i(t,0),n=Lr(r);return"81"==e?{rfc822:n}:"82"==e?{dns:n}:"86"==e?{uri:n}:"87"==e?{ip:zr(r)}:"a4"==e?{dn:this.getX500Name(r)}:void 0},this.getExtSubjectAltName2=function(){var t,e,r,s=this.getExtInfo("subjectAltName");if(void 0===s)return s;for(var a=new Array,u=o(this.hex,s.vidx),c=n(u,0),h=0;h<c.length;h++)r=u.substr(c[h],2),t=i(u,c[h]),"81"===r&&(e=Dr(t),a.push(["MAIL",e])),"82"===r&&(e=Dr(t),a.push(["DNS",e])),"84"===r&&(e=on.hex2dn(t,0),a.push(["DN",e])),"86"===r&&(e=Dr(t),a.push(["URI",e])),"87"===r&&(e=zr(t),a.push(["IP",e]));return a},this.getExtCRLDistributionPoints=function(t,e){if(void 0===t&&void 0===e){var r=this.getExtInfo("cRLDistributionPoints");if(void 0===r)return;t=o(this.hex,r.vidx),e=r.critical}var i={extname:"cRLDistributionPoints",array:[]};e&&(i.critical=!0);for(var s=n(t,0),a=0;a<s.length;a++){var u=o(t,s[a]);i.array.push(this.getDistributionPoint(u))}return i},this.getDistributionPoint=function(t){for(var e={},r=n(t,0),i=0;i<r.length;i++){var s=t.substr(r[i],2),a=o(t,r[i]);"a0"==s&&(e.dpname=this.getDistributionPointName(a))}return e},this.getDistributionPointName=function(t){for(var e={},r=n(t,0),i=0;i<r.length;i++){var s=t.substr(r[i],2),a=o(t,r[i]);"a0"==s&&(e.full=this.getGeneralNames(a))}return e},this.getExtCRLDistributionPointsURI=function(){var t=this.getExtInfo("cRLDistributionPoints");if(void 0===t)return t;for(var e=new Array,r=n(this.hex,t.vidx),i=0;i<r.length;i++)try{var o=Dr(s(this.hex,r[i],[0,0,0],"86"));e.push(o)}catch(t){}return e},this.getExtAIAInfo=function(){var t=this.getExtInfo("authorityInfoAccess");if(void 0===t)return t;for(var e={ocsp:[],caissuer:[]},r=n(this.hex,t.vidx),i=0;i<r.length;i++){var o=s(this.hex,r[i],[0],"06"),a=s(this.hex,r[i],[1],"86");"2b06010505073001"===o&&e.ocsp.push(Dr(a)),"2b06010505073002"===o&&e.caissuer.push(Dr(a))}return e},this.getExtAuthorityInfoAccess=function(t,e){if(void 0===t&&void 0===e){var r=this.getExtInfo("authorityInfoAccess");if(void 0===r)return;t=o(this.hex,r.vidx),e=r.critical}var i={extname:"authorityInfoAccess",array:[]};e&&(i.critical=!0);for(var u=n(t,0),c=0;c<u.length;c++){var h=a(t,u[c],[0],"06"),l=Dr(s(t,u[c],[1],"86"));if("2b06010505073001"==h)i.array.push({ocsp:l});else{if("2b06010505073002"!=h)throw new Error("unknown method: "+h);i.array.push({caissuer:l})}}return i},this.getExtCertificatePolicies=function(t,e){if(void 0===t&&void 0===e){var r=this.getExtInfo("certificatePolicies");if(void 0===r)return;t=o(this.hex,r.vidx),e=r.critical}var i={extname:"certificatePolicies",array:[]};e&&(i.critical=!0);for(var s=n(t,0),a=0;a<s.length;a++){var u=o(t,s[a]),c=this.getPolicyInformation(u);i.array.push(c)}return i},this.getPolicyInformation=function(t){var e={},r=s(t,0,[0],"06");e.policyoid=d(r);var i=l(t,0,[1],"30");if(-1!=i){e.array=[];for(var a=n(t,i),u=0;u<a.length;u++){var c=o(t,a[u]),h=this.getPolicyQualifierInfo(c);e.array.push(h)}}return e},this.getPolicyQualifierInfo=function(t){var e={},r=s(t,0,[0],"06");if("2b06010505070201"===r){var n=a(t,0,[1],"16");e.cps=Lr(n)}else if("2b06010505070202"===r){var i=u(t,0,[1],"30");e.unotice=this.getUserNotice(i)}return e},this.getUserNotice=function(t){for(var e={},r=n(t,0),i=0;i<r.length;i++){var s=o(t,r[i]);"30"!=s.substr(0,2)&&(e.exptext=this.getDisplayText(s))}return e},this.getDisplayText=function(t){var e={};return e.type={"0c":"utf8",16:"ia5","1a":"vis","1e":"bmp"}[t.substr(0,2)],e.str=Lr(i(t,0)),e},this.getExtCRLNumber=function(t,e){var r={extname:"cRLNumber"};if(e&&(r.critical=!0),"02"==t.substr(0,2))return r.num={hex:i(t,0)},r;throw new Error("hExtV parse error: "+t)},this.getExtCRLReason=function(t,e){var r={extname:"cRLReason"};if(e&&(r.critical=!0),"0a"==t.substr(0,2))return r.code=parseInt(i(t,0),16),r;throw new Error("hExtV parse error: "+t)},this.getExtOcspNonce=function(t,e){var r={extname:"ocspNonce"};e&&(r.critical=!0);var n=i(t,0);return r.hex=n,r},this.getExtOcspNoCheck=function(t,e){var r={extname:"ocspNoCheck"};return e&&(r.critical=!0),r},this.getExtAdobeTimeStamp=function(t,e){if(void 0===t&&void 0===e){var r=this.getExtInfo("adobeTimeStamp");if(void 0===r)return;t=o(this.hex,r.vidx),e=r.critical}var i={extname:"adobeTimeStamp"};e&&(i.critical=!0);var s=n(t,0);if(s.length>1){var a=o(t,s[1]),u=this.getGeneralName(a);null!=u.uri&&(i.uri=u.uri)}if(s.length>2){var c=o(t,s[2]);"0101ff"==c&&(i.reqauth=!0),"010100"==c&&(i.reqauth=!1)}return i},this.getX500NameRule=function(t){for(var e=null,r=[],n=0;n<t.length;n++)for(var i=t[n],o=0;o<i.length;o++)r.push(i[o]);for(n=0;n<r.length;n++){var s=r[n],a=s.ds,u=s.value,c=s.type;if(":"+a,"prn"!=a&&"utf8"!=a&&"ia5"!=a)return"mixed";if("ia5"==a){if("CN"!=c)return"mixed";if(Sr.lang.String.isMail(u))continue;return"mixed"}if("C"==c){if("prn"==a)continue;return"mixed"}if(":"+a,null==e)e=a;else if(e!==a)return"mixed"}return null==e?"prn":e},this.getX500Name=function(t){var e=this.getX500NameArray(t);return{array:e,str:this.dnarraytostr(e)}},this.getX500NameArray=function(t){for(var e=[],r=n(t,0),i=0;i<r.length;i++)e.push(this.getRDN(o(t,r[i])));return e},this.getRDN=function(t){for(var e=[],r=n(t,0),i=0;i<r.length;i++)e.push(this.getAttrTypeAndValue(o(t,r[i])));return e},this.getAttrTypeAndValue=function(t){var e={type:null,value:null,ds:null},r=n(t,0),i=s(t,r[0],[],"06"),o=s(t,r[1],[]),a=Sr.asn1.ASN1Util.oidHexToInt(i);return e.type=Sr.asn1.x509.OID.oid2atype(a),e.ds=this.HEX2STAG[t.substr(r[1],2)],"bmp"!=e.ds?e.value=Dr(o):e.value=Yr(o),e},this.readCertPEM=function(t){this.readCertHex(v(t))},this.readCertHex=function(t){this.hex=t,this.getVersion();try{h(this.hex,0,[0,7],"a3"),this.parseExt()}catch(t){}},this.getParam=function(){var t={};return t.version=this.getVersion(),t.serial={hex:this.getSerialNumberHex()},t.sigalg=this.getSignatureAlgorithmField(),t.issuer=this.getIssuer(),t.notbefore=this.getNotBefore(),t.notafter=this.getNotAfter(),t.subject=this.getSubject(),t.sbjpubkey=jr(this.getPublicKeyHex(),"PUBLIC KEY"),this.aExtInfo.length>0&&(t.ext=this.getExtParamArray()),t.sighex=this.getSignatureValueHex(),t},this.getExtParamArray=function(t){null==t&&(-1!=l(this.hex,0,[0,"[3]"])&&(t=c(this.hex,0,[0,"[3]",0],"30")));for(var e=[],r=n(t,0),i=0;i<r.length;i++){var s=o(t,r[i]),a=this.getExtParam(s);null!=a&&e.push(a)}return e},this.getExtParam=function(t){var e=n(t,0).length;if(2!=e&&3!=e)throw new Error("wrong number elements in Extension: "+e+" "+t);var r=p(s(t,0,[0],"06")),i=!1;3==e&&"0101ff"==u(t,0,[1])&&(i=!0);var o=u(t,0,[e-1,0]),a=void 0;if("2.5.29.14"==r?a=this.getExtSubjectKeyIdentifier(o,i):"2.5.29.15"==r?a=this.getExtKeyUsage(o,i):"2.5.29.17"==r?a=this.getExtSubjectAltName(o,i):"2.5.29.18"==r?a=this.getExtIssuerAltName(o,i):"2.5.29.19"==r?a=this.getExtBasicConstraints(o,i):"2.5.29.31"==r?a=this.getExtCRLDistributionPoints(o,i):"2.5.29.32"==r?a=this.getExtCertificatePolicies(o,i):"2.5.29.35"==r?a=this.getExtAuthorityKeyIdentifier(o,i):"2.5.29.37"==r?a=this.getExtExtKeyUsage(o,i):"1.3.6.1.5.5.7.1.1"==r?a=this.getExtAuthorityInfoAccess(o,i):"2.5.29.20"==r?a=this.getExtCRLNumber(o,i):"2.5.29.21"==r?a=this.getExtCRLReason(o,i):"1.3.6.1.5.5.7.48.1.2"==r?a=this.getExtOcspNonce(o,i):"1.3.6.1.5.5.7.48.1.5"==r?a=this.getExtOcspNoCheck(o,i):"1.2.840.113583.1.1.9.1"==r&&(a=this.getExtAdobeTimeStamp(o,i)),null!=a)return a;var c={extname:r,extn:o};return i&&(c.critical=!0),c},this.findExt=function(t,e){for(var r=0;r<t.length;r++)if(t[r].extname==e)return t[r];return null},this.updateExtCDPFullURI=function(t,e){var r=this.findExt(t,"cRLDistributionPoints");if(null!=r&&null!=r.array)for(var n=r.array,i=0;i<n.length;i++)if(null!=n[i].dpname&&null!=n[i].dpname.full)for(var o=n[i].dpname.full,s=0;s<o.length;s++){var a=o[i];null!=a.uri&&(a.uri=e)}},this.updateExtAIAOCSP=function(t,e){var r=this.findExt(t,"authorityInfoAccess");if(null!=r&&null!=r.array)for(var n=r.array,i=0;i<n.length;i++)null!=n[i].ocsp&&(n[i].ocsp=e)},this.updateExtAIACAIssuer=function(t,e){var r=this.findExt(t,"authorityInfoAccess");if(null!=r&&null!=r.array)for(var n=r.array,i=0;i<n.length;i++)null!=n[i].caissuer&&(n[i].caissuer=e)},this.dnarraytostr=function(t){return"/"+t.map((function(t){return function e(t){return t.map((function(t){return function e(t){return t.type+"="+t.value}(t).replace(/\+/,"\\+")})).join("+")}(t).replace(/\//,"\\/")})).join("/")},this.getInfo=function(){var t,e,r,n=function t(e){return JSON.stringify(e.array).replace(/[\[\]\{\}\"]/g,"")},i=function t(e){for(var r="",n=e.array,i=0;i<n.length;i++){var o=n[i];if(r+="    policy oid: "+o.policyoid+"\n",void 0!==o.array)for(var s=0;s<o.array.length;s++){var a=o.array[s];void 0!==a.cps&&(r+="    cps: "+a.cps+"\n")}}return r},o=function t(e){for(var r="",n=e.array,i=0;i<n.length;i++){var o=n[i];try{void 0!==o.dpname.full[0].uri&&(r+="    "+o.dpname.full[0].uri+"\n")}catch(t){}try{void 0!==o.dname.full[0].dn.hex&&(r+="    "+on.hex2dn(o.dpname.full[0].dn.hex)+"\n")}catch(t){}}return r},s=function t(e){for(var r="",n=e.array,i=0;i<n.length;i++){var o=n[i];void 0!==o.caissuer&&(r+="    caissuer: "+o.caissuer+"\n"),void 0!==o.ocsp&&(r+="    ocsp: "+o.ocsp+"\n")}return r};if(t="Basic Fields\n",t+="  serial number: "+this.getSerialNumberHex()+"\n",t+="  signature algorithm: "+this.getSignatureAlgorithmField()+"\n",t+="  issuer: "+this.getIssuerString()+"\n",t+="  notBefore: "+this.getNotBefore()+"\n",t+="  notAfter: "+this.getNotAfter()+"\n",t+="  subject: "+this.getSubjectString()+"\n",t+="  subject public key info: \n",t+="    key algorithm: "+(e=this.getPublicKey()).type+"\n","RSA"===e.type&&(t+="    n="+$r(e.n.toString(16)).substr(0,16)+"...\n",t+="    e="+$r(e.e.toString(16))+"\n"),null!=(r=this.aExtInfo)){t+="X509v3 Extensions:\n";for(var a=0;a<r.length;a++){var u=r[a],c=Sr.asn1.x509.OID.oid2name(u.oid);""===c&&(c=u.oid);var h="";if(!0===u.critical&&(h="CRITICAL"),t+="  "+c+" "+h+":\n","basicConstraints"===c){var l=this.getExtBasicConstraints();void 0===l.cA?t+="    {}\n":(t+="    cA=true",void 0!==l.pathLen&&(t+=", pathLen="+l.pathLen),t+="\n")}else if("keyUsage"===c)t+="    "+this.getExtKeyUsageString()+"\n";else if("subjectKeyIdentifier"===c)t+="    "+this.getExtSubjectKeyIdentifier().kid.hex+"\n";else if("authorityKeyIdentifier"===c){var f=this.getExtAuthorityKeyIdentifier();void 0!==f.kid&&(t+="    kid="+f.kid.hex+"\n")}else{if("extKeyUsage"===c)t+="    "+this.getExtExtKeyUsage().array.join(", ")+"\n";else if("subjectAltName"===c)t+="    "+n(this.getExtSubjectAltName())+"\n";else if("cRLDistributionPoints"===c)t+=o(this.getExtCRLDistributionPoints());else if("authorityInfoAccess"===c)t+=s(this.getExtAuthorityInfoAccess());else"certificatePolicies"===c&&(t+=i(this.getExtCertificatePolicies()))}}}return t+="signature algorithm: "+this.getSignatureAlgorithmName()+"\n",t+="signature: "+this.getSignatureValueHex().substr(0,16)+"...\n"},"string"==typeof t&&(-1!=t.indexOf("-----BEGIN")?this.readCertPEM(t):Sr.lang.String.isHex(t)&&this.readCertHex(t))}Me.prototype.sign=function(t,e){var r=function t(r){return Sr.crypto.Util.hashString(r,e)}(t);return this.signWithMessageHash(r,e)},Me.prototype.signWithMessageHash=function(t,e){var r=Oe(Sr.crypto.Util.getPaddedDigestInfoHex(t,e,this.n.bitLength()),16);return en(this.doPrivate(r).toString(16),this.n.bitLength())},Me.prototype.signPSS=function(t,e,r){var n=function t(r){return Sr.crypto.Util.hashHex(r,e)}(Nr(t));return void 0===r&&(r=-1),this.signWithMessageHashPSS(n,e,r)},Me.prototype.signWithMessageHashPSS=function(t,e,r){var n,i=Lr(t),o=i.length,s=this.n.bitLength()-1,a=Math.ceil(s/8),u=function t(r){return Sr.crypto.Util.hashHex(r,e)};if(-1===r||void 0===r)r=o;else if(-2===r)r=a-o-2;else if(r<-2)throw new Error("invalid salt length");if(a<o+r+2)throw new Error("data too long");var c="";r>0&&(c=new Array(r),(new Be).nextBytes(c),c=String.fromCharCode.apply(String,c));var h=Lr(u(Nr("\0\0\0\0\0\0\0\0"+i+c))),l=[];for(n=0;n<a-r-o-2;n+=1)l[n]=0;var f=String.fromCharCode.apply(String,l)+""+c,g=rn(h,f.length,u),d=[];for(n=0;n<f.length;n+=1)d[n]=f.charCodeAt(n)^g.charCodeAt(n);var p=65280>>8*a-s&255;for(d[0]&=~p,n=0;n<o;n++)d.push(h.charCodeAt(n));return d.push(188),en(this.doPrivate(new w(d)).toString(16),this.n.bitLength())},Me.prototype.verify=function(t,e){if(null==(e=e.toLowerCase()).match(/^[0-9a-f]+$/))return!1;var r=Oe(e,16),n=this.n.bitLength();if(r.bitLength()>n)return!1;var i=this.doPublic(r).toString(16);if(i.length+3!=n/4)return!1;var o=nn(i.replace(/^1f+00/,""));if(0==o.length)return!1;var s=o[0];return o[1]==function t(e){return Sr.crypto.Util.hashString(e,s)}(t)},Me.prototype.verifyWithMessageHash=function(t,e){if(e.length!=Math.ceil(this.n.bitLength()/4))return!1;var r=Oe(e,16);if(r.bitLength()>this.n.bitLength())return 0;var n=nn(this.doPublic(r).toString(16).replace(/^1f+00/,""));if(0==n.length)return!1;n[0];return n[1]==t},Me.prototype.verifyPSS=function(t,e,r,n){var i=function t(e){return Sr.crypto.Util.hashHex(e,r)}(Nr(t));return void 0===n&&(n=-1),this.verifyWithMessageHashPSS(i,e,r,n)},Me.prototype.verifyWithMessageHashPSS=function(t,e,r,n){if(e.length!=Math.ceil(this.n.bitLength()/4))return!1;var i,o=new w(e,16),s=function t(e){return Sr.crypto.Util.hashHex(e,r)},a=Lr(t),u=a.length,c=this.n.bitLength()-1,h=Math.ceil(c/8);if(-1===n||void 0===n)n=u;else if(-2===n)n=h-u-2;else if(n<-2)throw new Error("invalid salt length");if(h<u+n+2)throw new Error("data too long");var l=this.doPublic(o).toByteArray();for(i=0;i<l.length;i+=1)l[i]&=255;for(;l.length<h;)l.unshift(0);if(188!==l[h-1])throw new Error("encoded message does not end in 0xbc");var f=(l=String.fromCharCode.apply(String,l)).substr(0,h-u-1),g=l.substr(f.length,u),d=65280>>8*h-c&255;if(0!=(f.charCodeAt(0)&d))throw new Error("bits beyond keysize not zero");var p=rn(g,f.length,s),v=[];for(i=0;i<f.length;i+=1)v[i]=f.charCodeAt(i)^p.charCodeAt(i);v[0]&=~d;var y=h-u-n-2;for(i=0;i<y;i+=1)if(0!==v[i])throw new Error("leftmost octets not zero");if(1!==v[y])throw new Error("0x01 marker not found");return g===Lr(s(Nr("\0\0\0\0\0\0\0\0"+a+String.fromCharCode.apply(String,v.slice(-n)))))},Me.SALT_LEN_HLEN=-1,Me.SALT_LEN_MAX=-2,Me.SALT_LEN_RECOVER=-2,on.hex2dn=function(t,e){void 0===e&&(e=0);var r=new on;Fr.getTLV(t,e);return r.getX500Name(t).str},on.hex2rdn=function(t,e){if(void 0===e&&(e=0),"31"!==t.substr(e,2))throw new Error("malformed RDN");for(var r=new Array,n=Fr.getChildIdx(t,e),i=0;i<n.length;i++)r.push(on.hex2attrTypeValue(t,n[i]));return(r=r.map((function(t){return t.replace("+","\\+")}))).join("+")},on.hex2attrTypeValue=function(t,e){var r=Fr,n=r.getV;if(void 0===e&&(e=0),"30"!==t.substr(e,2))throw new Error("malformed attribute type and value");var i=r.getChildIdx(t,e);2!==i.length||t.substr(i[0],2);var o=n(t,i[0]),s=Sr.asn1.ASN1Util.oidHexToInt(o);return Sr.asn1.x509.OID.oid2atype(s)+"="+Lr(n(t,i[1]))},on.getPublicKeyFromCertHex=function(t){var e=new on;return e.readCertHex(t),e.getPublicKey()},on.getPublicKeyFromCertPEM=function(t){var e=new on;return e.readCertPEM(t),e.getPublicKey()},on.getPublicKeyInfoPropOfCertPEM=function(t){var e,r,n=Fr.getVbyList,i={};return i.algparam=null,(e=new on).readCertPEM(t),r=e.getPublicKeyHex(),i.keyhex=n(r,0,[1],"03").substr(2),i.algoid=n(r,0,[0,0],"06"),"2a8648ce3d0201"===i.algoid&&(i.algparam=n(r,0,[0,1],"06")),i},on.KEYUSAGE_NAME=["digitalSignature","nonRepudiation","keyEncipherment","dataEncipherment","keyAgreement","keyCertSign","cRLSign","encipherOnly","decipherOnly"],void 0!==Sr&&Sr||(e.KJUR=Sr={}),void 0!==Sr.jws&&Sr.jws||(Sr.jws={}),Sr.jws.JWS=function(){var t=Sr.jws.JWS.isSafeJSONString;this.parseJWS=function(e,r){if(void 0===this.parsedJWS||!r&&void 0===this.parsedJWS.sigvalH){var n=e.match(/^([^.]+)\.([^.]+)\.([^.]+)$/);if(null==n)throw"JWS signature is not a form of 'Head.Payload.SigValue'.";var i=n[1],o=n[2],s=n[3],a=i+"."+o;if(this.parsedJWS={},this.parsedJWS.headB64U=i,this.parsedJWS.payloadB64U=o,this.parsedJWS.sigvalB64U=s,this.parsedJWS.si=a,!r){var u=Rr(s),c=Oe(u,16);this.parsedJWS.sigvalH=u,this.parsedJWS.sigvalBI=c}var h=wr(i),l=wr(o);if(this.parsedJWS.headS=h,this.parsedJWS.payloadS=l,!t(h,this.parsedJWS,"headP"))throw"malformed JSON string for JWS Head: "+h}}},Sr.jws.JWS.sign=function(t,e,r,n,i){var o,s,a,u=Sr,c=u.jws.JWS,h=c.readSafeJSONString,l=c.isSafeJSONString,f=u.crypto,d=(f.ECDSA,f.Mac),p=f.Signature,v=JSON;if("string"!=typeof e&&"object"!=(void 0===e?"undefined":g(e)))throw"spHeader must be JSON string or object: "+e;if("object"==(void 0===e?"undefined":g(e))&&(s=e,o=v.stringify(s)),"string"==typeof e){if(!l(o=e))throw"JWS Head is not safe JSON string: "+o;s=h(o)}if(a=r,"object"==(void 0===r?"undefined":g(r))&&(a=v.stringify(r)),""!=t&&null!=t||void 0===s.alg||(t=s.alg),""!=t&&null!=t&&void 0===s.alg&&(s.alg=t,o=v.stringify(s)),t!==s.alg)throw"alg and sHeader.alg doesn't match: "+t+"!="+s.alg;var y=null;if(void 0===c.jwsalg2sigalg[t])throw"unsupported alg name: "+t;y=c.jwsalg2sigalg[t];var m=br(o)+"."+br(a),_="";if("Hmac"==y.substr(0,4)){if(void 0===n)throw"mac key shall be specified for HS* alg";var S=new d({alg:y,prov:"cryptojs",pass:n});S.updateString(m),_=S.doFinal()}else if(-1!=y.indexOf("withECDSA")){(w=new p({alg:y})).init(n,i),w.updateString(m);var b=w.sign();_=Sr.crypto.ECDSA.asn1SigToConcatSig(b)}else{var w;if("none"!=y)(w=new p({alg:y})).init(n,i),w.updateString(m),_=w.sign()}return m+"."+Tr(_)},Sr.jws.JWS.verify=function(t,e,r){var n,i=Sr,o=i.jws.JWS,s=o.readSafeJSONString,a=i.crypto,u=a.ECDSA,c=a.Mac,h=a.Signature;void 0!==g(Me)&&(n=Me);var l=t.split(".");if(3!==l.length)return!1;var f=l[0]+"."+l[1],d=Rr(l[2]),p=s(wr(l[0])),v=null,y=null;if(void 0===p.alg)throw"algorithm not specified in header";if((y=(v=p.alg).substr(0,2),null!=r&&"[object Array]"===Object.prototype.toString.call(r)&&r.length>0)&&-1==(":"+r.join(":")+":").indexOf(":"+v+":"))throw"algorithm '"+v+"' not accepted in the list";if("none"!=v&&null===e)throw"key shall be specified to verify.";if("string"==typeof e&&-1!=e.indexOf("-----BEGIN ")&&(e=tn.getKey(e)),!("RS"!=y&&"PS"!=y||e instanceof n))throw"key shall be a RSAKey obj for RS* and PS* algs";if("ES"==y&&!(e instanceof u))throw"key shall be a ECDSA obj for ES* algs";var m=null;if(void 0===o.jwsalg2sigalg[p.alg])throw"unsupported alg name: "+v;if("none"==(m=o.jwsalg2sigalg[v]))throw"not supported";if("Hmac"==m.substr(0,4)){if(void 0===e)throw"hexadecimal key shall be specified for HMAC";var _=new c({alg:m,pass:e});return _.updateString(f),d==_.doFinal()}if(-1!=m.indexOf("withECDSA")){var S,b=null;try{b=u.concatSigToASN1Sig(d)}catch(t){return!1}return(S=new h({alg:m})).init(e),S.updateString(f),S.verify(b)}return(S=new h({alg:m})).init(e),S.updateString(f),S.verify(d)},Sr.jws.JWS.parse=function(t){var e,r,n,i=t.split("."),o={};if(2!=i.length&&3!=i.length)throw"malformed sJWS: wrong number of '.' splitted elements";return e=i[0],r=i[1],3==i.length&&(n=i[2]),o.headerObj=Sr.jws.JWS.readSafeJSONString(wr(e)),o.payloadObj=Sr.jws.JWS.readSafeJSONString(wr(r)),o.headerPP=JSON.stringify(o.headerObj,null,"  "),null==o.payloadObj?o.payloadPP=wr(r):o.payloadPP=JSON.stringify(o.payloadObj,null,"  "),void 0!==n&&(o.sigHex=Rr(n)),o},Sr.jws.JWS.verifyJWT=function(t,e,r){var n=Sr.jws,i=n.JWS,o=i.readSafeJSONString,s=i.inArray,a=i.includedArray,u=t.split("."),c=u[0],h=u[1],l=(Rr(u[2]),o(wr(c))),f=o(wr(h));if(void 0===l.alg)return!1;if(void 0===r.alg)throw"acceptField.alg shall be specified";if(!s(l.alg,r.alg))return!1;if(void 0!==f.iss&&"object"===g(r.iss)&&!s(f.iss,r.iss))return!1;if(void 0!==f.sub&&"object"===g(r.sub)&&!s(f.sub,r.sub))return!1;if(void 0!==f.aud&&"object"===g(r.aud))if("string"==typeof f.aud){if(!s(f.aud,r.aud))return!1}else if("object"==g(f.aud)&&!a(f.aud,r.aud))return!1;var d=n.IntDate.getNow();return void 0!==r.verifyAt&&"number"==typeof r.verifyAt&&(d=r.verifyAt),void 0!==r.gracePeriod&&"number"==typeof r.gracePeriod||(r.gracePeriod=0),!(void 0!==f.exp&&"number"==typeof f.exp&&f.exp+r.gracePeriod<d)&&(!(void 0!==f.nbf&&"number"==typeof f.nbf&&d<f.nbf-r.gracePeriod)&&(!(void 0!==f.iat&&"number"==typeof f.iat&&d<f.iat-r.gracePeriod)&&((void 0===f.jti||void 0===r.jti||f.jti===r.jti)&&!!i.verify(t,e,r.alg))))},Sr.jws.JWS.includedArray=function(t,e){var r=Sr.jws.JWS.inArray;if(null===t)return!1;if("object"!==(void 0===t?"undefined":g(t)))return!1;if("number"!=typeof t.length)return!1;for(var n=0;n<t.length;n++)if(!r(t[n],e))return!1;return!0},Sr.jws.JWS.inArray=function(t,e){if(null===e)return!1;if("object"!==(void 0===e?"undefined":g(e)))return!1;if("number"!=typeof e.length)return!1;for(var r=0;r<e.length;r++)if(e[r]==t)return!0;return!1},Sr.jws.JWS.jwsalg2sigalg={HS256:"HmacSHA256",HS384:"HmacSHA384",HS512:"HmacSHA512",RS256:"SHA256withRSA",RS384:"SHA384withRSA",RS512:"SHA512withRSA",ES256:"SHA256withECDSA",ES384:"SHA384withECDSA",PS256:"SHA256withRSAandMGF1",PS384:"SHA384withRSAandMGF1",PS512:"SHA512withRSAandMGF1",none:"none"},Sr.jws.JWS.isSafeJSONString=function(t,e,r){var n=null;try{return"object"!=(void 0===(n=_r(t))?"undefined":g(n))||n.constructor===Array?0:(e&&(e[r]=n),1)}catch(t){return 0}},Sr.jws.JWS.readSafeJSONString=function(t){var e=null;try{return"object"!=(void 0===(e=_r(t))?"undefined":g(e))||e.constructor===Array?null:e}catch(t){return null}},Sr.jws.JWS.getEncodedSignatureValueFromJWS=function(t){var e=t.match(/^[^.]+\.[^.]+\.([^.]+)$/);if(null==e)throw"JWS signature is not a form of 'Head.Payload.SigValue'.";return e[1]},Sr.jws.JWS.getJWKthumbprint=function(t){if("RSA"!==t.kty&&"EC"!==t.kty&&"oct"!==t.kty)throw"unsupported algorithm for JWK Thumprint";var e="{";if("RSA"===t.kty){if("string"!=typeof t.n||"string"!=typeof t.e)throw"wrong n and e value for RSA key";e+='"e":"'+t.e+'",',e+='"kty":"'+t.kty+'",',e+='"n":"'+t.n+'"}'}else if("EC"===t.kty){if("string"!=typeof t.crv||"string"!=typeof t.x||"string"!=typeof t.y)throw"wrong crv, x and y value for EC key";e+='"crv":"'+t.crv+'",',e+='"kty":"'+t.kty+'",',e+='"x":"'+t.x+'",',e+='"y":"'+t.y+'"}'}else if("oct"===t.kty){if("string"!=typeof t.k)throw"wrong k value for oct(symmetric) key";e+='"kty":"'+t.kty+'",',e+='"k":"'+t.k+'"}'}var r=Nr(e);return Tr(Sr.crypto.Util.hashHex(r,"sha256"))},Sr.jws.IntDate={},Sr.jws.IntDate.get=function(t){var e=Sr.jws.IntDate,r=e.getNow,n=e.getZulu;if("now"==t)return r();if("now + 1hour"==t)return r()+3600;if("now + 1day"==t)return r()+86400;if("now + 1month"==t)return r()+2592e3;if("now + 1year"==t)return r()+31536e3;if(t.match(/Z$/))return n(t);if(t.match(/^[0-9]+$/))return parseInt(t);throw"unsupported format: "+t},Sr.jws.IntDate.getZulu=function(t){return Vr(t)},Sr.jws.IntDate.getNow=function(){return~~(new Date/1e3)},Sr.jws.IntDate.intDate2UTCString=function(t){return new Date(1e3*t).toUTCString()},Sr.jws.IntDate.intDate2Zulu=function(t){var e=new Date(1e3*t);return("0000"+e.getUTCFullYear()).slice(-4)+("00"+(e.getUTCMonth()+1)).slice(-2)+("00"+e.getUTCDate()).slice(-2)+("00"+e.getUTCHours()).slice(-2)+("00"+e.getUTCMinutes()).slice(-2)+("00"+e.getUTCSeconds()).slice(-2)+"Z"},e.SecureRandom=Be,e.rng_seed_time=Re,e.BigInteger=w,e.RSAKey=Me;var sn=Sr.crypto.EDSA;e.EDSA=sn;var an=Sr.crypto.DSA;e.DSA=an;var un=Sr.crypto.Signature;e.Signature=un;var cn=Sr.crypto.MessageDigest;e.MessageDigest=cn;var hn=Sr.crypto.Mac;e.Mac=hn;var ln=Sr.crypto.Cipher;e.Cipher=ln,e.KEYUTIL=tn,e.ASN1HEX=Fr,e.X509=on,e.CryptoJS=v,e.b64tohex=S,e.b64toBA=b,e.stoBA=Er,e.BAtos=xr,e.BAtohex=Ar,e.stohex=kr,e.stob64=function fn(t){return _(kr(t))},e.stob64u=function gn(t){return Pr(_(kr(t)))},e.b64utos=function dn(t){return xr(b(Cr(t)))},e.b64tob64u=Pr,e.b64utob64=Cr,e.hex2b64=_,e.hextob64u=Tr,e.b64utohex=Rr,e.utf8tob64u=br,e.b64utoutf8=wr,e.utf8tob64=function pn(t){return _(Kr(Gr(t)))},e.b64toutf8=function vn(t){return decodeURIComponent(qr(S(t)))},e.utf8tohex=Ir,e.hextoutf8=Dr,e.hextorstr=Lr,e.rstrtohex=Nr,e.hextob64=Ur,e.hextob64nl=Br,e.b64nltohex=Or,e.hextopem=jr,e.pemtohex=Mr,e.hextoArrayBuffer=function yn(t){if(t.length%2!=0)throw"input is not even length";if(null==t.match(/^[0-9A-Fa-f]+$/))throw"input is not hexadecimal";for(var e=new ArrayBuffer(t.length/2),r=new DataView(e),n=0;n<t.length/2;n++)r.setUint8(n,parseInt(t.substr(2*n,2),16));return e},e.ArrayBuffertohex=function mn(t){for(var e="",r=new DataView(t),n=0;n<t.byteLength;n++)e+=("00"+r.getUint8(n).toString(16)).slice(-2);return e},e.zulutomsec=Hr,e.zulutosec=Vr,e.zulutodate=function _n(t){return new Date(Hr(t))},e.datetozulu=function Sn(t,e,r){var n,i=t.getUTCFullYear();if(e){if(i<1950||2049<i)throw"not proper year for UTCTime: "+i;n=(""+i).slice(-2)}else n=("000"+i).slice(-4);if(n+=("0"+(t.getUTCMonth()+1)).slice(-2),n+=("0"+t.getUTCDate()).slice(-2),n+=("0"+t.getUTCHours()).slice(-2),n+=("0"+t.getUTCMinutes()).slice(-2),n+=("0"+t.getUTCSeconds()).slice(-2),r){var o=t.getUTCMilliseconds();0!==o&&(n+="."+(o=(o=("00"+o).slice(-3)).replace(/0+$/g,"")))}return n+="Z"},e.uricmptohex=Kr,e.hextouricmp=qr,e.ipv6tohex=Jr,e.hextoipv6=Wr,e.hextoip=zr,e.iptohex=function bn(t){var e="malformed IP address";if(!(t=t.toLowerCase(t)).match(/^[0-9.]+$/)){if(t.match(/^[0-9a-f:]+$/)&&-1!==t.indexOf(":"))return Jr(t);throw e}var r=t.split(".");if(4!==r.length)throw e;var n="";try{for(var i=0;i<4;i++){n+=("0"+parseInt(r[i]).toString(16)).slice(-2)}return n}catch(t){throw e}},e.encodeURIComponentAll=Gr,e.newline_toUnix=function wn(t){return t=t.replace(/\r\n/gm,"\n")},e.newline_toDos=function Fn(t){return t=(t=t.replace(/\r\n/gm,"\n")).replace(/\n/gm,"\r\n")},e.hextoposhex=$r,e.intarystrtohex=function En(t){t=(t=(t=t.replace(/^\s*\[\s*/,"")).replace(/\s*\]\s*$/,"")).replace(/\s*/g,"");try{return t.split(/,/).map((function(t,e,r){var n=parseInt(t);if(n<0||255<n)throw"integer not in range 0-255";return("00"+n.toString(16)).slice(-2)})).join("")}catch(t){throw"malformed integer array string: "+t}},e.strdiffidx=function t(e,r){var n=e.length;e.length>r.length&&(n=r.length);for(var i=0;i<n;i++)if(e.charCodeAt(i)!=r.charCodeAt(i))return i;return e.length!=r.length?n:-1},e.KJUR=Sr;var xn=Sr.crypto;e.crypto=xn;var An=Sr.asn1;e.asn1=An;var kn=Sr.jws;e.jws=kn;var Pn=Sr.lang;e.lang=Pn}).call(this,r(28).Buffer)},function(t,e,r){"use strict";(function(t){
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <http://feross.org>
 * @license  MIT
 */
var n=r(30),i=r(31),o=r(32);function s(){return u.TYPED_ARRAY_SUPPORT?2147483647:1073741823}function a(t,e){if(s()<e)throw new RangeError("Invalid typed array length");return u.TYPED_ARRAY_SUPPORT?(t=new Uint8Array(e)).__proto__=u.prototype:(null===t&&(t=new u(e)),t.length=e),t}function u(t,e,r){if(!(u.TYPED_ARRAY_SUPPORT||this instanceof u))return new u(t,e,r);if("number"==typeof t){if("string"==typeof e)throw new Error("If encoding is specified then the first argument must be a string");return l(this,t)}return c(this,t,e,r)}function c(t,e,r,n){if("number"==typeof e)throw new TypeError('"value" argument must not be a number');return"undefined"!=typeof ArrayBuffer&&e instanceof ArrayBuffer?function i(t,e,r,n){if(e.byteLength,r<0||e.byteLength<r)throw new RangeError("'offset' is out of bounds");if(e.byteLength<r+(n||0))throw new RangeError("'length' is out of bounds");e=void 0===r&&void 0===n?new Uint8Array(e):void 0===n?new Uint8Array(e,r):new Uint8Array(e,r,n);u.TYPED_ARRAY_SUPPORT?(t=e).__proto__=u.prototype:t=f(t,e);return t}(t,e,r,n):"string"==typeof e?function s(t,e,r){"string"==typeof r&&""!==r||(r="utf8");if(!u.isEncoding(r))throw new TypeError('"encoding" must be a valid string encoding');var n=0|d(e,r),i=(t=a(t,n)).write(e,r);i!==n&&(t=t.slice(0,i));return t}(t,e,r):function c(t,e){if(u.isBuffer(e)){var r=0|g(e.length);return 0===(t=a(t,r)).length||e.copy(t,0,0,r),t}if(e){if("undefined"!=typeof ArrayBuffer&&e.buffer instanceof ArrayBuffer||"length"in e)return"number"!=typeof e.length||function n(t){return t!=t}(e.length)?a(t,0):f(t,e);if("Buffer"===e.type&&o(e.data))return f(t,e.data)}throw new TypeError("First argument must be a string, Buffer, ArrayBuffer, Array, or array-like object.")}(t,e)}function h(t){if("number"!=typeof t)throw new TypeError('"size" argument must be a number');if(t<0)throw new RangeError('"size" argument must not be negative')}function l(t,e){if(h(e),t=a(t,e<0?0:0|g(e)),!u.TYPED_ARRAY_SUPPORT)for(var r=0;r<e;++r)t[r]=0;return t}function f(t,e){var r=e.length<0?0:0|g(e.length);t=a(t,r);for(var n=0;n<r;n+=1)t[n]=255&e[n];return t}function g(t){if(t>=s())throw new RangeError("Attempt to allocate Buffer larger than maximum size: 0x"+s().toString(16)+" bytes");return 0|t}function d(t,e){if(u.isBuffer(t))return t.length;if("undefined"!=typeof ArrayBuffer&&"function"==typeof ArrayBuffer.isView&&(ArrayBuffer.isView(t)||t instanceof ArrayBuffer))return t.byteLength;"string"!=typeof t&&(t=""+t);var r=t.length;if(0===r)return 0;for(var n=!1;;)switch(e){case"ascii":case"latin1":case"binary":return r;case"utf8":case"utf-8":case void 0:return K(t).length;case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return 2*r;case"hex":return r>>>1;case"base64":return q(t).length;default:if(n)return K(t).length;e=(""+e).toLowerCase(),n=!0}}function p(t,e,r){var n=!1;if((void 0===e||e<0)&&(e=0),e>this.length)return"";if((void 0===r||r>this.length)&&(r=this.length),r<=0)return"";if((r>>>=0)<=(e>>>=0))return"";for(t||(t="utf8");;)switch(t){case"hex":return I(this,e,r);case"utf8":case"utf-8":return A(this,e,r);case"ascii":return T(this,e,r);case"latin1":case"binary":return R(this,e,r);case"base64":return x(this,e,r);case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return D(this,e,r);default:if(n)throw new TypeError("Unknown encoding: "+t);t=(t+"").toLowerCase(),n=!0}}function v(t,e,r){var n=t[e];t[e]=t[r],t[r]=n}function y(t,e,r,n,i){if(0===t.length)return-1;if("string"==typeof r?(n=r,r=0):r>2147483647?r=2147483647:r<-2147483648&&(r=-2147483648),r=+r,isNaN(r)&&(r=i?0:t.length-1),r<0&&(r=t.length+r),r>=t.length){if(i)return-1;r=t.length-1}else if(r<0){if(!i)return-1;r=0}if("string"==typeof e&&(e=u.from(e,n)),u.isBuffer(e))return 0===e.length?-1:m(t,e,r,n,i);if("number"==typeof e)return e&=255,u.TYPED_ARRAY_SUPPORT&&"function"==typeof Uint8Array.prototype.indexOf?i?Uint8Array.prototype.indexOf.call(t,e,r):Uint8Array.prototype.lastIndexOf.call(t,e,r):m(t,[e],r,n,i);throw new TypeError("val must be string, number or Buffer")}function m(t,e,r,n,i){var o,s=1,a=t.length,u=e.length;if(void 0!==n&&("ucs2"===(n=String(n).toLowerCase())||"ucs-2"===n||"utf16le"===n||"utf-16le"===n)){if(t.length<2||e.length<2)return-1;s=2,a/=2,u/=2,r/=2}function c(t,e){return 1===s?t[e]:t.readUInt16BE(e*s)}if(i){var h=-1;for(o=r;o<a;o++)if(c(t,o)===c(e,-1===h?0:o-h)){if(-1===h&&(h=o),o-h+1===u)return h*s}else-1!==h&&(o-=o-h),h=-1}else for(r+u>a&&(r=a-u),o=r;o>=0;o--){for(var l=!0,f=0;f<u;f++)if(c(t,o+f)!==c(e,f)){l=!1;break}if(l)return o}return-1}function _(t,e,r,n){r=Number(r)||0;var i=t.length-r;n?(n=Number(n))>i&&(n=i):n=i;var o=e.length;if(o%2!=0)throw new TypeError("Invalid hex string");n>o/2&&(n=o/2);for(var s=0;s<n;++s){var a=parseInt(e.substr(2*s,2),16);if(isNaN(a))return s;t[r+s]=a}return s}function S(t,e,r,n){return J(K(e,t.length-r),t,r,n)}function b(t,e,r,n){return J(function i(t){for(var e=[],r=0;r<t.length;++r)e.push(255&t.charCodeAt(r));return e}(e),t,r,n)}function w(t,e,r,n){return b(t,e,r,n)}function F(t,e,r,n){return J(q(e),t,r,n)}function E(t,e,r,n){return J(function i(t,e){for(var r,n,i,o=[],s=0;s<t.length&&!((e-=2)<0);++s)n=(r=t.charCodeAt(s))>>8,i=r%256,o.push(i),o.push(n);return o}(e,t.length-r),t,r,n)}function x(t,e,r){return 0===e&&r===t.length?n.fromByteArray(t):n.fromByteArray(t.slice(e,r))}function A(t,e,r){r=Math.min(t.length,r);for(var n=[],i=e;i<r;){var o,s,a,u,c=t[i],h=null,l=c>239?4:c>223?3:c>191?2:1;if(i+l<=r)switch(l){case 1:c<128&&(h=c);break;case 2:128==(192&(o=t[i+1]))&&(u=(31&c)<<6|63&o)>127&&(h=u);break;case 3:o=t[i+1],s=t[i+2],128==(192&o)&&128==(192&s)&&(u=(15&c)<<12|(63&o)<<6|63&s)>2047&&(u<55296||u>57343)&&(h=u);break;case 4:o=t[i+1],s=t[i+2],a=t[i+3],128==(192&o)&&128==(192&s)&&128==(192&a)&&(u=(15&c)<<18|(63&o)<<12|(63&s)<<6|63&a)>65535&&u<1114112&&(h=u)}null===h?(h=65533,l=1):h>65535&&(h-=65536,n.push(h>>>10&1023|55296),h=56320|1023&h),n.push(h),i+=l}return function f(t){var e=t.length;if(e<=C)return String.fromCharCode.apply(String,t);var r="",n=0;for(;n<e;)r+=String.fromCharCode.apply(String,t.slice(n,n+=C));return r}(n)}e.Buffer=u,e.SlowBuffer=function k(t){+t!=t&&(t=0);return u.alloc(+t)},e.INSPECT_MAX_BYTES=50,u.TYPED_ARRAY_SUPPORT=void 0!==t.TYPED_ARRAY_SUPPORT?t.TYPED_ARRAY_SUPPORT:function P(){try{var t=new Uint8Array(1);return t.__proto__={__proto__:Uint8Array.prototype,foo:function(){return 42}},42===t.foo()&&"function"==typeof t.subarray&&0===t.subarray(1,1).byteLength}catch(t){return!1}}(),e.kMaxLength=s(),u.poolSize=8192,u._augment=function(t){return t.__proto__=u.prototype,t},u.from=function(t,e,r){return c(null,t,e,r)},u.TYPED_ARRAY_SUPPORT&&(u.prototype.__proto__=Uint8Array.prototype,u.__proto__=Uint8Array,"undefined"!=typeof Symbol&&Symbol.species&&u[Symbol.species]===u&&Object.defineProperty(u,Symbol.species,{value:null,configurable:!0})),u.alloc=function(t,e,r){return function n(t,e,r,i){return h(e),e<=0?a(t,e):void 0!==r?"string"==typeof i?a(t,e).fill(r,i):a(t,e).fill(r):a(t,e)}(null,t,e,r)},u.allocUnsafe=function(t){return l(null,t)},u.allocUnsafeSlow=function(t){return l(null,t)},u.isBuffer=function t(e){return!(null==e||!e._isBuffer)},u.compare=function t(e,r){if(!u.isBuffer(e)||!u.isBuffer(r))throw new TypeError("Arguments must be Buffers");if(e===r)return 0;for(var n=e.length,i=r.length,o=0,s=Math.min(n,i);o<s;++o)if(e[o]!==r[o]){n=e[o],i=r[o];break}return n<i?-1:i<n?1:0},u.isEncoding=function t(e){switch(String(e).toLowerCase()){case"hex":case"utf8":case"utf-8":case"ascii":case"latin1":case"binary":case"base64":case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return!0;default:return!1}},u.concat=function t(e,r){if(!o(e))throw new TypeError('"list" argument must be an Array of Buffers');if(0===e.length)return u.alloc(0);var n;if(void 0===r)for(r=0,n=0;n<e.length;++n)r+=e[n].length;var i=u.allocUnsafe(r),s=0;for(n=0;n<e.length;++n){var a=e[n];if(!u.isBuffer(a))throw new TypeError('"list" argument must be an Array of Buffers');a.copy(i,s),s+=a.length}return i},u.byteLength=d,u.prototype._isBuffer=!0,u.prototype.swap16=function t(){var e=this.length;if(e%2!=0)throw new RangeError("Buffer size must be a multiple of 16-bits");for(var r=0;r<e;r+=2)v(this,r,r+1);return this},u.prototype.swap32=function t(){var e=this.length;if(e%4!=0)throw new RangeError("Buffer size must be a multiple of 32-bits");for(var r=0;r<e;r+=4)v(this,r,r+3),v(this,r+1,r+2);return this},u.prototype.swap64=function t(){var e=this.length;if(e%8!=0)throw new RangeError("Buffer size must be a multiple of 64-bits");for(var r=0;r<e;r+=8)v(this,r,r+7),v(this,r+1,r+6),v(this,r+2,r+5),v(this,r+3,r+4);return this},u.prototype.toString=function t(){var e=0|this.length;return 0===e?"":0===arguments.length?A(this,0,e):p.apply(this,arguments)},u.prototype.equals=function t(e){if(!u.isBuffer(e))throw new TypeError("Argument must be a Buffer");return this===e||0===u.compare(this,e)},u.prototype.inspect=function t(){var r="",n=e.INSPECT_MAX_BYTES;return this.length>0&&(r=this.toString("hex",0,n).match(/.{2}/g).join(" "),this.length>n&&(r+=" ... ")),"<Buffer "+r+">"},u.prototype.compare=function t(e,r,n,i,o){if(!u.isBuffer(e))throw new TypeError("Argument must be a Buffer");if(void 0===r&&(r=0),void 0===n&&(n=e?e.length:0),void 0===i&&(i=0),void 0===o&&(o=this.length),r<0||n>e.length||i<0||o>this.length)throw new RangeError("out of range index");if(i>=o&&r>=n)return 0;if(i>=o)return-1;if(r>=n)return 1;if(this===e)return 0;for(var s=(o>>>=0)-(i>>>=0),a=(n>>>=0)-(r>>>=0),c=Math.min(s,a),h=this.slice(i,o),l=e.slice(r,n),f=0;f<c;++f)if(h[f]!==l[f]){s=h[f],a=l[f];break}return s<a?-1:a<s?1:0},u.prototype.includes=function t(e,r,n){return-1!==this.indexOf(e,r,n)},u.prototype.indexOf=function t(e,r,n){return y(this,e,r,n,!0)},u.prototype.lastIndexOf=function t(e,r,n){return y(this,e,r,n,!1)},u.prototype.write=function t(e,r,n,i){if(void 0===r)i="utf8",n=this.length,r=0;else if(void 0===n&&"string"==typeof r)i=r,n=this.length,r=0;else{if(!isFinite(r))throw new Error("Buffer.write(string, encoding, offset[, length]) is no longer supported");r|=0,isFinite(n)?(n|=0,void 0===i&&(i="utf8")):(i=n,n=void 0)}var o=this.length-r;if((void 0===n||n>o)&&(n=o),e.length>0&&(n<0||r<0)||r>this.length)throw new RangeError("Attempt to write outside buffer bounds");i||(i="utf8");for(var s=!1;;)switch(i){case"hex":return _(this,e,r,n);case"utf8":case"utf-8":return S(this,e,r,n);case"ascii":return b(this,e,r,n);case"latin1":case"binary":return w(this,e,r,n);case"base64":return F(this,e,r,n);case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return E(this,e,r,n);default:if(s)throw new TypeError("Unknown encoding: "+i);i=(""+i).toLowerCase(),s=!0}},u.prototype.toJSON=function t(){return{type:"Buffer",data:Array.prototype.slice.call(this._arr||this,0)}};var C=4096;function T(t,e,r){var n="";r=Math.min(t.length,r);for(var i=e;i<r;++i)n+=String.fromCharCode(127&t[i]);return n}function R(t,e,r){var n="";r=Math.min(t.length,r);for(var i=e;i<r;++i)n+=String.fromCharCode(t[i]);return n}function I(t,e,r){var n=t.length;(!e||e<0)&&(e=0),(!r||r<0||r>n)&&(r=n);for(var i="",o=e;o<r;++o)i+=V(t[o]);return i}function D(t,e,r){for(var n=t.slice(e,r),i="",o=0;o<n.length;o+=2)i+=String.fromCharCode(n[o]+256*n[o+1]);return i}function L(t,e,r){if(t%1!=0||t<0)throw new RangeError("offset is not uint");if(t+e>r)throw new RangeError("Trying to access beyond buffer length")}function N(t,e,r,n,i,o){if(!u.isBuffer(t))throw new TypeError('"buffer" argument must be a Buffer instance');if(e>i||e<o)throw new RangeError('"value" argument is out of bounds');if(r+n>t.length)throw new RangeError("Index out of range")}function U(t,e,r,n){e<0&&(e=65535+e+1);for(var i=0,o=Math.min(t.length-r,2);i<o;++i)t[r+i]=(e&255<<8*(n?i:1-i))>>>8*(n?i:1-i)}function B(t,e,r,n){e<0&&(e=4294967295+e+1);for(var i=0,o=Math.min(t.length-r,4);i<o;++i)t[r+i]=e>>>8*(n?i:3-i)&255}function O(t,e,r,n,i,o){if(r+n>t.length)throw new RangeError("Index out of range");if(r<0)throw new RangeError("Index out of range")}function j(t,e,r,n,o){return o||O(t,0,r,4),i.write(t,e,r,n,23,4),r+4}function M(t,e,r,n,o){return o||O(t,0,r,8),i.write(t,e,r,n,52,8),r+8}u.prototype.slice=function t(e,r){var n,i=this.length;if((e=~~e)<0?(e+=i)<0&&(e=0):e>i&&(e=i),(r=void 0===r?i:~~r)<0?(r+=i)<0&&(r=0):r>i&&(r=i),r<e&&(r=e),u.TYPED_ARRAY_SUPPORT)(n=this.subarray(e,r)).__proto__=u.prototype;else{var o=r-e;n=new u(o,void 0);for(var s=0;s<o;++s)n[s]=this[s+e]}return n},u.prototype.readUIntLE=function t(e,r,n){e|=0,r|=0,n||L(e,r,this.length);for(var i=this[e],o=1,s=0;++s<r&&(o*=256);)i+=this[e+s]*o;return i},u.prototype.readUIntBE=function t(e,r,n){e|=0,r|=0,n||L(e,r,this.length);for(var i=this[e+--r],o=1;r>0&&(o*=256);)i+=this[e+--r]*o;return i},u.prototype.readUInt8=function t(e,r){return r||L(e,1,this.length),this[e]},u.prototype.readUInt16LE=function t(e,r){return r||L(e,2,this.length),this[e]|this[e+1]<<8},u.prototype.readUInt16BE=function t(e,r){return r||L(e,2,this.length),this[e]<<8|this[e+1]},u.prototype.readUInt32LE=function t(e,r){return r||L(e,4,this.length),(this[e]|this[e+1]<<8|this[e+2]<<16)+16777216*this[e+3]},u.prototype.readUInt32BE=function t(e,r){return r||L(e,4,this.length),16777216*this[e]+(this[e+1]<<16|this[e+2]<<8|this[e+3])},u.prototype.readIntLE=function t(e,r,n){e|=0,r|=0,n||L(e,r,this.length);for(var i=this[e],o=1,s=0;++s<r&&(o*=256);)i+=this[e+s]*o;return i>=(o*=128)&&(i-=Math.pow(2,8*r)),i},u.prototype.readIntBE=function t(e,r,n){e|=0,r|=0,n||L(e,r,this.length);for(var i=r,o=1,s=this[e+--i];i>0&&(o*=256);)s+=this[e+--i]*o;return s>=(o*=128)&&(s-=Math.pow(2,8*r)),s},u.prototype.readInt8=function t(e,r){return r||L(e,1,this.length),128&this[e]?-1*(255-this[e]+1):this[e]},u.prototype.readInt16LE=function t(e,r){r||L(e,2,this.length);var n=this[e]|this[e+1]<<8;return 32768&n?4294901760|n:n},u.prototype.readInt16BE=function t(e,r){r||L(e,2,this.length);var n=this[e+1]|this[e]<<8;return 32768&n?4294901760|n:n},u.prototype.readInt32LE=function t(e,r){return r||L(e,4,this.length),this[e]|this[e+1]<<8|this[e+2]<<16|this[e+3]<<24},u.prototype.readInt32BE=function t(e,r){return r||L(e,4,this.length),this[e]<<24|this[e+1]<<16|this[e+2]<<8|this[e+3]},u.prototype.readFloatLE=function t(e,r){return r||L(e,4,this.length),i.read(this,e,!0,23,4)},u.prototype.readFloatBE=function t(e,r){return r||L(e,4,this.length),i.read(this,e,!1,23,4)},u.prototype.readDoubleLE=function t(e,r){return r||L(e,8,this.length),i.read(this,e,!0,52,8)},u.prototype.readDoubleBE=function t(e,r){return r||L(e,8,this.length),i.read(this,e,!1,52,8)},u.prototype.writeUIntLE=function t(e,r,n,i){(e=+e,r|=0,n|=0,i)||N(this,e,r,n,Math.pow(2,8*n)-1,0);var o=1,s=0;for(this[r]=255&e;++s<n&&(o*=256);)this[r+s]=e/o&255;return r+n},u.prototype.writeUIntBE=function t(e,r,n,i){(e=+e,r|=0,n|=0,i)||N(this,e,r,n,Math.pow(2,8*n)-1,0);var o=n-1,s=1;for(this[r+o]=255&e;--o>=0&&(s*=256);)this[r+o]=e/s&255;return r+n},u.prototype.writeUInt8=function t(e,r,n){return e=+e,r|=0,n||N(this,e,r,1,255,0),u.TYPED_ARRAY_SUPPORT||(e=Math.floor(e)),this[r]=255&e,r+1},u.prototype.writeUInt16LE=function t(e,r,n){return e=+e,r|=0,n||N(this,e,r,2,65535,0),u.TYPED_ARRAY_SUPPORT?(this[r]=255&e,this[r+1]=e>>>8):U(this,e,r,!0),r+2},u.prototype.writeUInt16BE=function t(e,r,n){return e=+e,r|=0,n||N(this,e,r,2,65535,0),u.TYPED_ARRAY_SUPPORT?(this[r]=e>>>8,this[r+1]=255&e):U(this,e,r,!1),r+2},u.prototype.writeUInt32LE=function t(e,r,n){return e=+e,r|=0,n||N(this,e,r,4,4294967295,0),u.TYPED_ARRAY_SUPPORT?(this[r+3]=e>>>24,this[r+2]=e>>>16,this[r+1]=e>>>8,this[r]=255&e):B(this,e,r,!0),r+4},u.prototype.writeUInt32BE=function t(e,r,n){return e=+e,r|=0,n||N(this,e,r,4,4294967295,0),u.TYPED_ARRAY_SUPPORT?(this[r]=e>>>24,this[r+1]=e>>>16,this[r+2]=e>>>8,this[r+3]=255&e):B(this,e,r,!1),r+4},u.prototype.writeIntLE=function t(e,r,n,i){if(e=+e,r|=0,!i){var o=Math.pow(2,8*n-1);N(this,e,r,n,o-1,-o)}var s=0,a=1,u=0;for(this[r]=255&e;++s<n&&(a*=256);)e<0&&0===u&&0!==this[r+s-1]&&(u=1),this[r+s]=(e/a>>0)-u&255;return r+n},u.prototype.writeIntBE=function t(e,r,n,i){if(e=+e,r|=0,!i){var o=Math.pow(2,8*n-1);N(this,e,r,n,o-1,-o)}var s=n-1,a=1,u=0;for(this[r+s]=255&e;--s>=0&&(a*=256);)e<0&&0===u&&0!==this[r+s+1]&&(u=1),this[r+s]=(e/a>>0)-u&255;return r+n},u.prototype.writeInt8=function t(e,r,n){return e=+e,r|=0,n||N(this,e,r,1,127,-128),u.TYPED_ARRAY_SUPPORT||(e=Math.floor(e)),e<0&&(e=255+e+1),this[r]=255&e,r+1},u.prototype.writeInt16LE=function t(e,r,n){return e=+e,r|=0,n||N(this,e,r,2,32767,-32768),u.TYPED_ARRAY_SUPPORT?(this[r]=255&e,this[r+1]=e>>>8):U(this,e,r,!0),r+2},u.prototype.writeInt16BE=function t(e,r,n){return e=+e,r|=0,n||N(this,e,r,2,32767,-32768),u.TYPED_ARRAY_SUPPORT?(this[r]=e>>>8,this[r+1]=255&e):U(this,e,r,!1),r+2},u.prototype.writeInt32LE=function t(e,r,n){return e=+e,r|=0,n||N(this,e,r,4,2147483647,-2147483648),u.TYPED_ARRAY_SUPPORT?(this[r]=255&e,this[r+1]=e>>>8,this[r+2]=e>>>16,this[r+3]=e>>>24):B(this,e,r,!0),r+4},u.prototype.writeInt32BE=function t(e,r,n){return e=+e,r|=0,n||N(this,e,r,4,2147483647,-2147483648),e<0&&(e=4294967295+e+1),u.TYPED_ARRAY_SUPPORT?(this[r]=e>>>24,this[r+1]=e>>>16,this[r+2]=e>>>8,this[r+3]=255&e):B(this,e,r,!1),r+4},u.prototype.writeFloatLE=function t(e,r,n){return j(this,e,r,!0,n)},u.prototype.writeFloatBE=function t(e,r,n){return j(this,e,r,!1,n)},u.prototype.writeDoubleLE=function t(e,r,n){return M(this,e,r,!0,n)},u.prototype.writeDoubleBE=function t(e,r,n){return M(this,e,r,!1,n)},u.prototype.copy=function t(e,r,n,i){if(n||(n=0),i||0===i||(i=this.length),r>=e.length&&(r=e.length),r||(r=0),i>0&&i<n&&(i=n),i===n)return 0;if(0===e.length||0===this.length)return 0;if(r<0)throw new RangeError("targetStart out of bounds");if(n<0||n>=this.length)throw new RangeError("sourceStart out of bounds");if(i<0)throw new RangeError("sourceEnd out of bounds");i>this.length&&(i=this.length),e.length-r<i-n&&(i=e.length-r+n);var o,s=i-n;if(this===e&&n<r&&r<i)for(o=s-1;o>=0;--o)e[o+r]=this[o+n];else if(s<1e3||!u.TYPED_ARRAY_SUPPORT)for(o=0;o<s;++o)e[o+r]=this[o+n];else Uint8Array.prototype.set.call(e,this.subarray(n,n+s),r);return s},u.prototype.fill=function t(e,r,n,i){if("string"==typeof e){if("string"==typeof r?(i=r,r=0,n=this.length):"string"==typeof n&&(i=n,n=this.length),1===e.length){var o=e.charCodeAt(0);o<256&&(e=o)}if(void 0!==i&&"string"!=typeof i)throw new TypeError("encoding must be a string");if("string"==typeof i&&!u.isEncoding(i))throw new TypeError("Unknown encoding: "+i)}else"number"==typeof e&&(e&=255);if(r<0||this.length<r||this.length<n)throw new RangeError("Out of range index");if(n<=r)return this;var s;if(r>>>=0,n=void 0===n?this.length:n>>>0,e||(e=0),"number"==typeof e)for(s=r;s<n;++s)this[s]=e;else{var a=u.isBuffer(e)?e:K(new u(e,i).toString()),c=a.length;for(s=0;s<n-r;++s)this[s+r]=a[s%c]}return this};var H=/[^+\/0-9A-Za-z-_]/g;function V(t){return t<16?"0"+t.toString(16):t.toString(16)}function K(t,e){var r;e=e||1/0;for(var n=t.length,i=null,o=[],s=0;s<n;++s){if((r=t.charCodeAt(s))>55295&&r<57344){if(!i){if(r>56319){(e-=3)>-1&&o.push(239,191,189);continue}if(s+1===n){(e-=3)>-1&&o.push(239,191,189);continue}i=r;continue}if(r<56320){(e-=3)>-1&&o.push(239,191,189),i=r;continue}r=65536+(i-55296<<10|r-56320)}else i&&(e-=3)>-1&&o.push(239,191,189);if(i=null,r<128){if((e-=1)<0)break;o.push(r)}else if(r<2048){if((e-=2)<0)break;o.push(r>>6|192,63&r|128)}else if(r<65536){if((e-=3)<0)break;o.push(r>>12|224,r>>6&63|128,63&r|128)}else{if(!(r<1114112))throw new Error("Invalid code point");if((e-=4)<0)break;o.push(r>>18|240,r>>12&63|128,r>>6&63|128,63&r|128)}}return o}function q(t){return n.toByteArray(function e(t){if((t=function e(t){return t.trim?t.trim():t.replace(/^\s+|\s+$/g,"")}(t).replace(H,"")).length<2)return"";for(;t.length%4!=0;)t+="=";return t}(t))}function J(t,e,r,n){for(var i=0;i<n&&!(i+r>=e.length||i>=t.length);++i)e[i+r]=t[i];return i}}).call(this,r(29))},function(t,e){var r;r=function(){return this}();try{r=r||new Function("return this")()}catch(t){"object"==typeof window&&(r=window)}t.exports=r},function(t,e,r){"use strict";e.byteLength=function n(t){var e=f(t),r=e[0],n=e[1];return 3*(r+n)/4-n},e.toByteArray=function i(t){var e,r,n=f(t),i=n[0],o=n[1],s=new u(function c(t,e,r){return 3*(e+r)/4-r}(0,i,o)),h=0,l=o>0?i-4:i;for(r=0;r<l;r+=4)e=a[t.charCodeAt(r)]<<18|a[t.charCodeAt(r+1)]<<12|a[t.charCodeAt(r+2)]<<6|a[t.charCodeAt(r+3)],s[h++]=e>>16&255,s[h++]=e>>8&255,s[h++]=255&e;2===o&&(e=a[t.charCodeAt(r)]<<2|a[t.charCodeAt(r+1)]>>4,s[h++]=255&e);1===o&&(e=a[t.charCodeAt(r)]<<10|a[t.charCodeAt(r+1)]<<4|a[t.charCodeAt(r+2)]>>2,s[h++]=e>>8&255,s[h++]=255&e);return s},e.fromByteArray=function o(t){for(var e,r=t.length,n=r%3,i=[],o=16383,a=0,u=r-n;a<u;a+=o)i.push(g(t,a,a+o>u?u:a+o));1===n?(e=t[r-1],i.push(s[e>>2]+s[e<<4&63]+"==")):2===n&&(e=(t[r-2]<<8)+t[r-1],i.push(s[e>>10]+s[e>>4&63]+s[e<<2&63]+"="));return i.join("")};for(var s=[],a=[],u="undefined"!=typeof Uint8Array?Uint8Array:Array,c="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",h=0,l=c.length;h<l;++h)s[h]=c[h],a[c.charCodeAt(h)]=h;function f(t){var e=t.length;if(e%4>0)throw new Error("Invalid string. Length must be a multiple of 4");var r=t.indexOf("=");return-1===r&&(r=e),[r,r===e?0:4-r%4]}function g(t,e,r){for(var n,i,o=[],a=e;a<r;a+=3)n=(t[a]<<16&16711680)+(t[a+1]<<8&65280)+(255&t[a+2]),o.push(s[(i=n)>>18&63]+s[i>>12&63]+s[i>>6&63]+s[63&i]);return o.join("")}a["-".charCodeAt(0)]=62,a["_".charCodeAt(0)]=63},function(t,e){
/*! ieee754. BSD-3-Clause License. Feross Aboukhadijeh <https://feross.org/opensource> */
e.read=function(t,e,r,n,i){var o,s,a=8*i-n-1,u=(1<<a)-1,c=u>>1,h=-7,l=r?i-1:0,f=r?-1:1,g=t[e+l];for(l+=f,o=g&(1<<-h)-1,g>>=-h,h+=a;h>0;o=256*o+t[e+l],l+=f,h-=8);for(s=o&(1<<-h)-1,o>>=-h,h+=n;h>0;s=256*s+t[e+l],l+=f,h-=8);if(0===o)o=1-c;else{if(o===u)return s?NaN:1/0*(g?-1:1);s+=Math.pow(2,n),o-=c}return(g?-1:1)*s*Math.pow(2,o-n)},e.write=function(t,e,r,n,i,o){var s,a,u,c=8*o-i-1,h=(1<<c)-1,l=h>>1,f=23===i?Math.pow(2,-24)-Math.pow(2,-77):0,g=n?0:o-1,d=n?1:-1,p=e<0||0===e&&1/e<0?1:0;for(e=Math.abs(e),isNaN(e)||e===1/0?(a=isNaN(e)?1:0,s=h):(s=Math.floor(Math.log(e)/Math.LN2),e*(u=Math.pow(2,-s))<1&&(s--,u*=2),(e+=s+l>=1?f/u:f*Math.pow(2,1-l))*u>=2&&(s++,u/=2),s+l>=h?(a=0,s=h):s+l>=1?(a=(e*u-1)*Math.pow(2,i),s+=l):(a=e*Math.pow(2,l-1)*Math.pow(2,i),s=0));i>=8;t[r+g]=255&a,g+=d,a/=256,i-=8);for(s=s<<i|a,c+=i;c>0;t[r+g]=255&s,g+=d,s/=256,c-=8);t[r+g-d]|=128*p}},function(t,e){var r={}.toString;t.exports=Array.isArray||function(t){return"[object Array]"==r.call(t)}},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.default=function n(t){var e=t.jws,r=t.KeyUtil,n=t.X509,o=t.crypto,s=t.hextob64u,a=t.b64tohex,u=t.AllowedSigningAlgs;return function(){function t(){!function e(t,r){if(!(t instanceof r))throw new TypeError("Cannot call a class as a function")}(this,t)}return t.parseJwt=function t(r){i.Log.debug("JoseUtil.parseJwt");try{var n=e.JWS.parse(r);return{header:n.headerObj,payload:n.payloadObj}}catch(t){i.Log.error(t)}},t.validateJwt=function e(o,s,u,c,h,l,f){i.Log.debug("JoseUtil.validateJwt");try{if("RSA"===s.kty)if(s.e&&s.n)s=r.getKey(s);else{if(!s.x5c||!s.x5c.length)return i.Log.error("JoseUtil.validateJwt: RSA key missing key material",s),Promise.reject(new Error("RSA key missing key material"));var g=a(s.x5c[0]);s=n.getPublicKeyFromCertHex(g)}else{if("EC"!==s.kty)return i.Log.error("JoseUtil.validateJwt: Unsupported key type",s&&s.kty),Promise.reject(new Error(s.kty));if(!(s.crv&&s.x&&s.y))return i.Log.error("JoseUtil.validateJwt: EC key missing key material",s),Promise.reject(new Error("EC key missing key material"));s=r.getKey(s)}return t._validateJwt(o,s,u,c,h,l,f)}catch(t){return i.Log.error(t&&t.message||t),Promise.reject("JWT validation failed")}},t.validateJwtAttributes=function e(r,n,o,s,a,u){s||(s=0),a||(a=parseInt(Date.now()/1e3));var c=t.parseJwt(r).payload;if(!c.iss)return i.Log.error("JoseUtil._validateJwt: issuer was not provided"),Promise.reject(new Error("issuer was not provided"));if(c.iss!==n)return i.Log.error("JoseUtil._validateJwt: Invalid issuer in token",c.iss),Promise.reject(new Error("Invalid issuer in token: "+c.iss));if(!c.aud)return i.Log.error("JoseUtil._validateJwt: aud was not provided"),Promise.reject(new Error("aud was not provided"));if(!(c.aud===o||Array.isArray(c.aud)&&c.aud.indexOf(o)>=0))return i.Log.error("JoseUtil._validateJwt: Invalid audience in token",c.aud),Promise.reject(new Error("Invalid audience in token: "+c.aud));if(c.azp&&c.azp!==o)return i.Log.error("JoseUtil._validateJwt: Invalid azp in token",c.azp),Promise.reject(new Error("Invalid azp in token: "+c.azp));if(!u){var h=a+s,l=a-s;if(!c.iat)return i.Log.error("JoseUtil._validateJwt: iat was not provided"),Promise.reject(new Error("iat was not provided"));if(h<c.iat)return i.Log.error("JoseUtil._validateJwt: iat is in the future",c.iat),Promise.reject(new Error("iat is in the future: "+c.iat));if(c.nbf&&h<c.nbf)return i.Log.error("JoseUtil._validateJwt: nbf is in the future",c.nbf),Promise.reject(new Error("nbf is in the future: "+c.nbf));if(!c.exp)return i.Log.error("JoseUtil._validateJwt: exp was not provided"),Promise.reject(new Error("exp was not provided"));if(c.exp<l)return i.Log.error("JoseUtil._validateJwt: exp is in the past",c.exp),Promise.reject(new Error("exp is in the past:"+c.exp))}return Promise.resolve(c)},t._validateJwt=function r(n,o,s,a,c,h,l){return t.validateJwtAttributes(n,s,a,c,h,l).then((function(t){try{return e.JWS.verify(n,o,u)?t:(i.Log.error("JoseUtil._validateJwt: signature validation failed"),Promise.reject(new Error("signature validation failed")))}catch(t){return i.Log.error(t&&t.message||t),Promise.reject(new Error("signature validation failed"))}}))},t.hashString=function t(e,r){try{return o.Util.hashString(e,r)}catch(t){i.Log.error(t)}},t.hexToBase64Url=function t(e){try{return s(e)}catch(t){i.Log.error(t)}},t}()};var i=r(0);t.exports=e.default},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.SigninResponse=void 0;var n=function(){function t(t,e){for(var r=0;r<e.length;r++){var n=e[r];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,r,n){return r&&t(e.prototype,r),n&&t(e,n),e}}(),i=r(3);function o(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}e.SigninResponse=function(){function t(e){var r=arguments.length>1&&void 0!==arguments[1]?arguments[1]:"#";o(this,t);var n=i.UrlUtility.parseUrlFragment(e,r);this.error=n.error,this.error_description=n.error_description,this.error_uri=n.error_uri,this.code=n.code,this.state=n.state,this.id_token=n.id_token,this.session_state=n.session_state,this.access_token=n.access_token,this.token_type=n.token_type,this.scope=n.scope,this.profile=void 0,this.expires_in=n.expires_in}return n(t,[{key:"expires_in",get:function t(){if(this.expires_at){var e=parseInt(Date.now()/1e3);return this.expires_at-e}},set:function t(e){var r=parseInt(e);if("number"==typeof r&&r>0){var n=parseInt(Date.now()/1e3);this.expires_at=n+r}}},{key:"expired",get:function t(){var e=this.expires_in;if(void 0!==e)return e<=0}},{key:"scopes",get:function t(){return(this.scope||"").split(" ")}},{key:"isOpenIdConnect",get:function t(){return this.scopes.indexOf("openid")>=0||!!this.id_token}}]),t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.SignoutRequest=void 0;var n=r(0),i=r(3),o=r(9);e.SignoutRequest=function t(e){var r=e.url,s=e.id_token_hint,a=e.post_logout_redirect_uri,u=e.data,c=e.extraQueryParams,h=e.request_type;if(function l(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}(this,t),!r)throw n.Log.error("SignoutRequest.ctor: No url passed"),new Error("url");for(var f in s&&(r=i.UrlUtility.addQueryParam(r,"id_token_hint",s)),a&&(r=i.UrlUtility.addQueryParam(r,"post_logout_redirect_uri",a),u&&(this.state=new o.State({data:u,request_type:h}),r=i.UrlUtility.addQueryParam(r,"state",this.state.id))),c)r=i.UrlUtility.addQueryParam(r,f,c[f]);this.url=r}},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.SignoutResponse=void 0;var n=r(3);e.SignoutResponse=function t(e){!function r(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}(this,t);var i=n.UrlUtility.parseUrlFragment(e,"?");this.error=i.error,this.error_description=i.error_description,this.error_uri=i.error_uri,this.state=i.state}},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.InMemoryWebStorage=void 0;var n=function(){function t(t,e){for(var r=0;r<e.length;r++){var n=e[r];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,r,n){return r&&t(e.prototype,r),n&&t(e,n),e}}(),i=r(0);e.InMemoryWebStorage=function(){function t(){!function e(t,r){if(!(t instanceof r))throw new TypeError("Cannot call a class as a function")}(this,t),this._data={}}return t.prototype.getItem=function t(e){return i.Log.debug("InMemoryWebStorage.getItem",e),this._data[e]},t.prototype.setItem=function t(e,r){i.Log.debug("InMemoryWebStorage.setItem",e),this._data[e]=r},t.prototype.removeItem=function t(e){i.Log.debug("InMemoryWebStorage.removeItem",e),delete this._data[e]},t.prototype.key=function t(e){return Object.getOwnPropertyNames(this._data)[e]},n(t,[{key:"length",get:function t(){return Object.getOwnPropertyNames(this._data).length}}]),t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.UserManager=void 0;var n=function(){function t(t,e){for(var r=0;r<e.length;r++){var n=e[r];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,r,n){return r&&t(e.prototype,r),n&&t(e,n),e}}(),i=r(0),o=r(10),s=r(39),a=r(15),u=r(45),c=r(47),h=r(18),l=r(8),f=r(20),g=r(11),d=r(4);function p(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function v(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}e.UserManager=function(t){function e(){var r=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},n=arguments.length>1&&void 0!==arguments[1]?arguments[1]:c.SilentRenewService,o=arguments.length>2&&void 0!==arguments[2]?arguments[2]:h.SessionMonitor,a=arguments.length>3&&void 0!==arguments[3]?arguments[3]:f.TokenRevocationClient,l=arguments.length>4&&void 0!==arguments[4]?arguments[4]:g.TokenClient,y=arguments.length>5&&void 0!==arguments[5]?arguments[5]:d.JoseUtil;p(this,e),r instanceof s.UserManagerSettings||(r=new s.UserManagerSettings(r));var m=v(this,t.call(this,r));return m._events=new u.UserManagerEvents(r),m._silentRenewService=new n(m),m.settings.automaticSilentRenew&&(i.Log.debug("UserManager.ctor: automaticSilentRenew is configured, setting up silent renew"),m.startSilentRenew()),m.settings.monitorSession&&(i.Log.debug("UserManager.ctor: monitorSession is configured, setting up session monitor"),m._sessionMonitor=new o(m)),m._tokenRevocationClient=new a(m._settings),m._tokenClient=new l(m._settings),m._joseUtil=y,m}return function r(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}(e,t),e.prototype.getUser=function t(){var e=this;return this._loadUser().then((function(t){return t?(i.Log.info("UserManager.getUser: user loaded"),e._events.load(t,!1),t):(i.Log.info("UserManager.getUser: user not found in storage"),null)}))},e.prototype.removeUser=function t(){var e=this;return this.storeUser(null).then((function(){i.Log.info("UserManager.removeUser: user removed from storage"),e._events.unload()}))},e.prototype.signinRedirect=function t(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{};(e=Object.assign({},e)).request_type="si:r";var r={useReplaceToNavigate:e.useReplaceToNavigate};return this._signinStart(e,this._redirectNavigator,r).then((function(){i.Log.info("UserManager.signinRedirect: successful")}))},e.prototype.signinRedirectCallback=function t(e){return this._signinEnd(e||this._redirectNavigator.url).then((function(t){return t.profile&&t.profile.sub?i.Log.info("UserManager.signinRedirectCallback: successful, signed in sub: ",t.profile.sub):i.Log.info("UserManager.signinRedirectCallback: no sub"),t}))},e.prototype.signinPopup=function t(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{};(e=Object.assign({},e)).request_type="si:p";var r=e.redirect_uri||this.settings.popup_redirect_uri||this.settings.redirect_uri;return r?(e.redirect_uri=r,e.display="popup",this._signin(e,this._popupNavigator,{startUrl:r,popupWindowFeatures:e.popupWindowFeatures||this.settings.popupWindowFeatures,popupWindowTarget:e.popupWindowTarget||this.settings.popupWindowTarget}).then((function(t){return t&&(t.profile&&t.profile.sub?i.Log.info("UserManager.signinPopup: signinPopup successful, signed in sub: ",t.profile.sub):i.Log.info("UserManager.signinPopup: no sub")),t}))):(i.Log.error("UserManager.signinPopup: No popup_redirect_uri or redirect_uri configured"),Promise.reject(new Error("No popup_redirect_uri or redirect_uri configured")))},e.prototype.signinPopupCallback=function t(e){return this._signinCallback(e,this._popupNavigator).then((function(t){return t&&(t.profile&&t.profile.sub?i.Log.info("UserManager.signinPopupCallback: successful, signed in sub: ",t.profile.sub):i.Log.info("UserManager.signinPopupCallback: no sub")),t})).catch((function(t){i.Log.error(t.message)}))},e.prototype.signinSilent=function t(){var e=this,r=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{};return r=Object.assign({},r),this._loadUser().then((function(t){return t&&t.refresh_token?(r.refresh_token=t.refresh_token,e._useRefreshToken(r)):(r.request_type="si:s",r.id_token_hint=r.id_token_hint||e.settings.includeIdTokenInSilentRenew&&t&&t.id_token,t&&e._settings.validateSubOnSilentRenew&&(i.Log.debug("UserManager.signinSilent, subject prior to silent renew: ",t.profile.sub),r.current_sub=t.profile.sub),e._signinSilentIframe(r))}))},e.prototype._useRefreshToken=function t(){var e=this,r=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{};return this._tokenClient.exchangeRefreshToken(r).then((function(t){return t?t.access_token?e._loadUser().then((function(r){if(r){var n=Promise.resolve();return t.id_token&&(n=e._validateIdTokenFromTokenRefreshToken(r.profile,t.id_token)),n.then((function(){return i.Log.debug("UserManager._useRefreshToken: refresh token response success"),r.id_token=t.id_token||r.id_token,r.access_token=t.access_token,r.refresh_token=t.refresh_token||r.refresh_token,r.expires_in=t.expires_in,e.storeUser(r).then((function(){return e._events.load(r),r}))}))}return null})):(i.Log.error("UserManager._useRefreshToken: No access token returned from token endpoint"),Promise.reject("No access token returned from token endpoint")):(i.Log.error("UserManager._useRefreshToken: No response returned from token endpoint"),Promise.reject("No response returned from token endpoint"))}))},e.prototype._validateIdTokenFromTokenRefreshToken=function t(e,r){var n=this;return this._metadataService.getIssuer().then((function(t){return n.settings.getEpochTime().then((function(o){return n._joseUtil.validateJwtAttributes(r,t,n._settings.client_id,n._settings.clockSkew,o).then((function(t){return t?t.sub!==e.sub?(i.Log.error("UserManager._validateIdTokenFromTokenRefreshToken: sub in id_token does not match current sub"),Promise.reject(new Error("sub in id_token does not match current sub"))):t.auth_time&&t.auth_time!==e.auth_time?(i.Log.error("UserManager._validateIdTokenFromTokenRefreshToken: auth_time in id_token does not match original auth_time"),Promise.reject(new Error("auth_time in id_token does not match original auth_time"))):t.azp&&t.azp!==e.azp?(i.Log.error("UserManager._validateIdTokenFromTokenRefreshToken: azp in id_token does not match original azp"),Promise.reject(new Error("azp in id_token does not match original azp"))):!t.azp&&e.azp?(i.Log.error("UserManager._validateIdTokenFromTokenRefreshToken: azp not in id_token, but present in original id_token"),Promise.reject(new Error("azp not in id_token, but present in original id_token"))):void 0:(i.Log.error("UserManager._validateIdTokenFromTokenRefreshToken: Failed to validate id_token"),Promise.reject(new Error("Failed to validate id_token")))}))}))}))},e.prototype._signinSilentIframe=function t(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},r=e.redirect_uri||this.settings.silent_redirect_uri||this.settings.redirect_uri;return r?(e.redirect_uri=r,e.prompt=e.prompt||"none",this._signin(e,this._iframeNavigator,{startUrl:r,silentRequestTimeout:e.silentRequestTimeout||this.settings.silentRequestTimeout}).then((function(t){return t&&(t.profile&&t.profile.sub?i.Log.info("UserManager.signinSilent: successful, signed in sub: ",t.profile.sub):i.Log.info("UserManager.signinSilent: no sub")),t}))):(i.Log.error("UserManager.signinSilent: No silent_redirect_uri configured"),Promise.reject(new Error("No silent_redirect_uri configured")))},e.prototype.signinSilentCallback=function t(e){return this._signinCallback(e,this._iframeNavigator).then((function(t){return t&&(t.profile&&t.profile.sub?i.Log.info("UserManager.signinSilentCallback: successful, signed in sub: ",t.profile.sub):i.Log.info("UserManager.signinSilentCallback: no sub")),t}))},e.prototype.signinCallback=function t(e){var r=this;return this.readSigninResponseState(e).then((function(t){var n=t.state;t.response;return"si:r"===n.request_type?r.signinRedirectCallback(e):"si:p"===n.request_type?r.signinPopupCallback(e):"si:s"===n.request_type?r.signinSilentCallback(e):Promise.reject(new Error("invalid response_type in state"))}))},e.prototype.signoutCallback=function t(e,r){var n=this;return this.readSignoutResponseState(e).then((function(t){var i=t.state,o=t.response;return i?"so:r"===i.request_type?n.signoutRedirectCallback(e):"so:p"===i.request_type?n.signoutPopupCallback(e,r):Promise.reject(new Error("invalid response_type in state")):o}))},e.prototype.querySessionStatus=function t(){var e=this,r=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{};(r=Object.assign({},r)).request_type="si:s";var n=r.redirect_uri||this.settings.silent_redirect_uri||this.settings.redirect_uri;return n?(r.redirect_uri=n,r.prompt="none",r.response_type=r.response_type||this.settings.query_status_response_type,r.scope=r.scope||"openid",r.skipUserInfo=!0,this._signinStart(r,this._iframeNavigator,{startUrl:n,silentRequestTimeout:r.silentRequestTimeout||this.settings.silentRequestTimeout}).then((function(t){return e.processSigninResponse(t.url).then((function(t){if(i.Log.debug("UserManager.querySessionStatus: got signin response"),t.session_state&&t.profile.sub)return i.Log.info("UserManager.querySessionStatus: querySessionStatus success for sub: ",t.profile.sub),{session_state:t.session_state,sub:t.profile.sub,sid:t.profile.sid};i.Log.info("querySessionStatus successful, user not authenticated")})).catch((function(t){if(t.session_state&&e.settings.monitorAnonymousSession&&("login_required"==t.message||"consent_required"==t.message||"interaction_required"==t.message||"account_selection_required"==t.message))return i.Log.info("UserManager.querySessionStatus: querySessionStatus success for anonymous user"),{session_state:t.session_state};throw t}))}))):(i.Log.error("UserManager.querySessionStatus: No silent_redirect_uri configured"),Promise.reject(new Error("No silent_redirect_uri configured")))},e.prototype._signin=function t(e,r){var n=this,i=arguments.length>2&&void 0!==arguments[2]?arguments[2]:{};return this._signinStart(e,r,i).then((function(t){return n._signinEnd(t.url,e)}))},e.prototype._signinStart=function t(e,r){var n=this,o=arguments.length>2&&void 0!==arguments[2]?arguments[2]:{};return r.prepare(o).then((function(t){return i.Log.debug("UserManager._signinStart: got navigator window handle"),n.createSigninRequest(e).then((function(e){return i.Log.debug("UserManager._signinStart: got signin request"),o.url=e.url,o.id=e.state.id,t.navigate(o)})).catch((function(e){throw t.close&&(i.Log.debug("UserManager._signinStart: Error after preparing navigator, closing navigator window"),t.close()),e}))}))},e.prototype._signinEnd=function t(e){var r=this,n=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{};return this.processSigninResponse(e).then((function(t){i.Log.debug("UserManager._signinEnd: got signin response");var e=new a.User(t);if(n.current_sub){if(n.current_sub!==e.profile.sub)return i.Log.debug("UserManager._signinEnd: current user does not match user returned from signin. sub from signin: ",e.profile.sub),Promise.reject(new Error("login_required"));i.Log.debug("UserManager._signinEnd: current user matches user returned from signin")}return r.storeUser(e).then((function(){return i.Log.debug("UserManager._signinEnd: user stored"),r._events.load(e),e}))}))},e.prototype._signinCallback=function t(e,r){i.Log.debug("UserManager._signinCallback");var n="query"===this._settings.response_mode||!this._settings.response_mode&&l.SigninRequest.isCode(this._settings.response_type)?"?":"#";return r.callback(e,void 0,n)},e.prototype.signoutRedirect=function t(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{};(e=Object.assign({},e)).request_type="so:r";var r=e.post_logout_redirect_uri||this.settings.post_logout_redirect_uri;r&&(e.post_logout_redirect_uri=r);var n={useReplaceToNavigate:e.useReplaceToNavigate};return this._signoutStart(e,this._redirectNavigator,n).then((function(){i.Log.info("UserManager.signoutRedirect: successful")}))},e.prototype.signoutRedirectCallback=function t(e){return this._signoutEnd(e||this._redirectNavigator.url).then((function(t){return i.Log.info("UserManager.signoutRedirectCallback: successful"),t}))},e.prototype.signoutPopup=function t(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{};(e=Object.assign({},e)).request_type="so:p";var r=e.post_logout_redirect_uri||this.settings.popup_post_logout_redirect_uri||this.settings.post_logout_redirect_uri;return e.post_logout_redirect_uri=r,e.display="popup",e.post_logout_redirect_uri&&(e.state=e.state||{}),this._signout(e,this._popupNavigator,{startUrl:r,popupWindowFeatures:e.popupWindowFeatures||this.settings.popupWindowFeatures,popupWindowTarget:e.popupWindowTarget||this.settings.popupWindowTarget}).then((function(){i.Log.info("UserManager.signoutPopup: successful")}))},e.prototype.signoutPopupCallback=function t(e,r){void 0===r&&"boolean"==typeof e&&(r=e,e=null);return this._popupNavigator.callback(e,r,"?").then((function(){i.Log.info("UserManager.signoutPopupCallback: successful")}))},e.prototype._signout=function t(e,r){var n=this,i=arguments.length>2&&void 0!==arguments[2]?arguments[2]:{};return this._signoutStart(e,r,i).then((function(t){return n._signoutEnd(t.url)}))},e.prototype._signoutStart=function t(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},r=this,n=arguments[1],o=arguments.length>2&&void 0!==arguments[2]?arguments[2]:{};return n.prepare(o).then((function(t){return i.Log.debug("UserManager._signoutStart: got navigator window handle"),r._loadUser().then((function(n){return i.Log.debug("UserManager._signoutStart: loaded current user from storage"),(r._settings.revokeAccessTokenOnSignout?r._revokeInternal(n):Promise.resolve()).then((function(){var s=e.id_token_hint||n&&n.id_token;return s&&(i.Log.debug("UserManager._signoutStart: Setting id_token into signout request"),e.id_token_hint=s),r.removeUser().then((function(){return i.Log.debug("UserManager._signoutStart: user removed, creating signout request"),r.createSignoutRequest(e).then((function(e){return i.Log.debug("UserManager._signoutStart: got signout request"),o.url=e.url,e.state&&(o.id=e.state.id),t.navigate(o)}))}))}))})).catch((function(e){throw t.close&&(i.Log.debug("UserManager._signoutStart: Error after preparing navigator, closing navigator window"),t.close()),e}))}))},e.prototype._signoutEnd=function t(e){return this.processSignoutResponse(e).then((function(t){return i.Log.debug("UserManager._signoutEnd: got signout response"),t}))},e.prototype.revokeAccessToken=function t(){var e=this;return this._loadUser().then((function(t){return e._revokeInternal(t,!0).then((function(r){if(r)return i.Log.debug("UserManager.revokeAccessToken: removing token properties from user and re-storing"),t.access_token=null,t.refresh_token=null,t.expires_at=null,t.token_type=null,e.storeUser(t).then((function(){i.Log.debug("UserManager.revokeAccessToken: user stored"),e._events.load(t)}))}))})).then((function(){i.Log.info("UserManager.revokeAccessToken: access token revoked successfully")}))},e.prototype._revokeInternal=function t(e,r){var n=this;if(e){var o=e.access_token,s=e.refresh_token;return this._revokeAccessTokenInternal(o,r).then((function(t){return n._revokeRefreshTokenInternal(s,r).then((function(e){return t||e||i.Log.debug("UserManager.revokeAccessToken: no need to revoke due to no token(s), or JWT format"),t||e}))}))}return Promise.resolve(!1)},e.prototype._revokeAccessTokenInternal=function t(e,r){return!e||e.indexOf(".")>=0?Promise.resolve(!1):this._tokenRevocationClient.revoke(e,r).then((function(){return!0}))},e.prototype._revokeRefreshTokenInternal=function t(e,r){return e?this._tokenRevocationClient.revoke(e,r,"refresh_token").then((function(){return!0})):Promise.resolve(!1)},e.prototype.startSilentRenew=function t(){this._silentRenewService.start()},e.prototype.stopSilentRenew=function t(){this._silentRenewService.stop()},e.prototype._loadUser=function t(){return this._userStore.get(this._userStoreKey).then((function(t){return t?(i.Log.debug("UserManager._loadUser: user storageString loaded"),a.User.fromStorageString(t)):(i.Log.debug("UserManager._loadUser: no user storageString"),null)}))},e.prototype.storeUser=function t(e){if(e){i.Log.debug("UserManager.storeUser: storing user");var r=e.toStorageString();return this._userStore.set(this._userStoreKey,r)}return i.Log.debug("storeUser.storeUser: removing user"),this._userStore.remove(this._userStoreKey)},n(e,[{key:"_redirectNavigator",get:function t(){return this.settings.redirectNavigator}},{key:"_popupNavigator",get:function t(){return this.settings.popupNavigator}},{key:"_iframeNavigator",get:function t(){return this.settings.iframeNavigator}},{key:"_userStore",get:function t(){return this.settings.userStore}},{key:"events",get:function t(){return this._events}},{key:"_userStoreKey",get:function t(){return"user:"+this.settings.authority+":"+this.settings.client_id}}]),e}(o.OidcClient)},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.UserManagerSettings=void 0;var n=function(){function t(t,e){for(var r=0;r<e.length;r++){var n=e[r];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,r,n){return r&&t(e.prototype,r),n&&t(e,n),e}}(),i=(r(0),r(5)),o=r(40),s=r(41),a=r(43),u=r(6),c=r(1),h=r(8);function l(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function f(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}e.UserManagerSettings=function(t){function e(){var r=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},n=r.popup_redirect_uri,i=r.popup_post_logout_redirect_uri,g=r.popupWindowFeatures,d=r.popupWindowTarget,p=r.silent_redirect_uri,v=r.silentRequestTimeout,y=r.automaticSilentRenew,m=void 0!==y&&y,_=r.validateSubOnSilentRenew,S=void 0!==_&&_,b=r.includeIdTokenInSilentRenew,w=void 0===b||b,F=r.monitorSession,E=void 0===F||F,x=r.monitorAnonymousSession,A=void 0!==x&&x,k=r.checkSessionInterval,P=void 0===k?2e3:k,C=r.stopCheckSessionOnError,T=void 0===C||C,R=r.query_status_response_type,I=r.revokeAccessTokenOnSignout,D=void 0!==I&&I,L=r.accessTokenExpiringNotificationTime,N=void 0===L?60:L,U=r.redirectNavigator,B=void 0===U?new o.RedirectNavigator:U,O=r.popupNavigator,j=void 0===O?new s.PopupNavigator:O,M=r.iframeNavigator,H=void 0===M?new a.IFrameNavigator:M,V=r.userStore,K=void 0===V?new u.WebStorageStateStore({store:c.Global.sessionStorage}):V;l(this,e);var q=f(this,t.call(this,arguments[0]));return q._popup_redirect_uri=n,q._popup_post_logout_redirect_uri=i,q._popupWindowFeatures=g,q._popupWindowTarget=d,q._silent_redirect_uri=p,q._silentRequestTimeout=v,q._automaticSilentRenew=m,q._validateSubOnSilentRenew=S,q._includeIdTokenInSilentRenew=w,q._accessTokenExpiringNotificationTime=N,q._monitorSession=E,q._monitorAnonymousSession=A,q._checkSessionInterval=P,q._stopCheckSessionOnError=T,R?q._query_status_response_type=R:arguments[0]&&arguments[0].response_type?q._query_status_response_type=h.SigninRequest.isOidc(arguments[0].response_type)?"id_token":"code":q._query_status_response_type="id_token",q._revokeAccessTokenOnSignout=D,q._redirectNavigator=B,q._popupNavigator=j,q._iframeNavigator=H,q._userStore=K,q}return function r(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}(e,t),n(e,[{key:"popup_redirect_uri",get:function t(){return this._popup_redirect_uri}},{key:"popup_post_logout_redirect_uri",get:function t(){return this._popup_post_logout_redirect_uri}},{key:"popupWindowFeatures",get:function t(){return this._popupWindowFeatures}},{key:"popupWindowTarget",get:function t(){return this._popupWindowTarget}},{key:"silent_redirect_uri",get:function t(){return this._silent_redirect_uri}},{key:"silentRequestTimeout",get:function t(){return this._silentRequestTimeout}},{key:"automaticSilentRenew",get:function t(){return this._automaticSilentRenew}},{key:"validateSubOnSilentRenew",get:function t(){return this._validateSubOnSilentRenew}},{key:"includeIdTokenInSilentRenew",get:function t(){return this._includeIdTokenInSilentRenew}},{key:"accessTokenExpiringNotificationTime",get:function t(){return this._accessTokenExpiringNotificationTime}},{key:"monitorSession",get:function t(){return this._monitorSession}},{key:"monitorAnonymousSession",get:function t(){return this._monitorAnonymousSession}},{key:"checkSessionInterval",get:function t(){return this._checkSessionInterval}},{key:"stopCheckSessionOnError",get:function t(){return this._stopCheckSessionOnError}},{key:"query_status_response_type",get:function t(){return this._query_status_response_type}},{key:"revokeAccessTokenOnSignout",get:function t(){return this._revokeAccessTokenOnSignout}},{key:"redirectNavigator",get:function t(){return this._redirectNavigator}},{key:"popupNavigator",get:function t(){return this._popupNavigator}},{key:"iframeNavigator",get:function t(){return this._iframeNavigator}},{key:"userStore",get:function t(){return this._userStore}}]),e}(i.OidcClientSettings)},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.RedirectNavigator=void 0;var n=function(){function t(t,e){for(var r=0;r<e.length;r++){var n=e[r];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,r,n){return r&&t(e.prototype,r),n&&t(e,n),e}}(),i=r(0);e.RedirectNavigator=function(){function t(){!function e(t,r){if(!(t instanceof r))throw new TypeError("Cannot call a class as a function")}(this,t)}return t.prototype.prepare=function t(){return Promise.resolve(this)},t.prototype.navigate=function t(e){return e&&e.url?(e.useReplaceToNavigate?window.location.replace(e.url):window.location=e.url,Promise.resolve()):(i.Log.error("RedirectNavigator.navigate: No url provided"),Promise.reject(new Error("No url provided")))},n(t,[{key:"url",get:function t(){return window.location.href}}]),t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.PopupNavigator=void 0;var n=r(0),i=r(42);e.PopupNavigator=function(){function t(){!function e(t,r){if(!(t instanceof r))throw new TypeError("Cannot call a class as a function")}(this,t)}return t.prototype.prepare=function t(e){var r=new i.PopupWindow(e);return Promise.resolve(r)},t.prototype.callback=function t(e,r,o){n.Log.debug("PopupNavigator.callback");try{return i.PopupWindow.notifyOpener(e,r,o),Promise.resolve()}catch(t){return Promise.reject(t)}},t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.PopupWindow=void 0;var n=function(){function t(t,e){for(var r=0;r<e.length;r++){var n=e[r];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,r,n){return r&&t(e.prototype,r),n&&t(e,n),e}}(),i=r(0),o=r(3);e.PopupWindow=function(){function t(e){var r=this;!function n(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}(this,t),this._promise=new Promise((function(t,e){r._resolve=t,r._reject=e}));var o=e.popupWindowTarget||"_blank",s=e.popupWindowFeatures||"location=no,toolbar=no,width=500,height=500,left=100,top=100;";this._popup=window.open("",o,s),this._popup&&(i.Log.debug("PopupWindow.ctor: popup successfully created"),this._checkForPopupClosedTimer=window.setInterval(this._checkForPopupClosed.bind(this),500))}return t.prototype.navigate=function t(e){return this._popup?e&&e.url?(i.Log.debug("PopupWindow.navigate: Setting URL in popup"),this._id=e.id,this._id&&(window["popupCallback_"+e.id]=this._callback.bind(this)),this._popup.focus(),this._popup.window.location=e.url):(this._error("PopupWindow.navigate: no url provided"),this._error("No url provided")):this._error("PopupWindow.navigate: Error opening popup window"),this.promise},t.prototype._success=function t(e){i.Log.debug("PopupWindow.callback: Successful response from popup window"),this._cleanup(),this._resolve(e)},t.prototype._error=function t(e){i.Log.error("PopupWindow.error: ",e),this._cleanup(),this._reject(new Error(e))},t.prototype.close=function t(){this._cleanup(!1)},t.prototype._cleanup=function t(e){i.Log.debug("PopupWindow.cleanup"),window.clearInterval(this._checkForPopupClosedTimer),this._checkForPopupClosedTimer=null,delete window["popupCallback_"+this._id],this._popup&&!e&&this._popup.close(),this._popup=null},t.prototype._checkForPopupClosed=function t(){this._popup&&!this._popup.closed||this._error("Popup window closed")},t.prototype._callback=function t(e,r){this._cleanup(r),e?(i.Log.debug("PopupWindow.callback success"),this._success({url:e})):(i.Log.debug("PopupWindow.callback: Invalid response from popup"),this._error("Invalid response from popup"))},t.notifyOpener=function t(e,r,n){if(window.opener){if(e=e||window.location.href){var s=o.UrlUtility.parseUrlFragment(e,n);if(s.state){var a="popupCallback_"+s.state,u=window.opener[a];u?(i.Log.debug("PopupWindow.notifyOpener: passing url message to opener"),u(e,r)):i.Log.warn("PopupWindow.notifyOpener: no matching callback found on opener")}else i.Log.warn("PopupWindow.notifyOpener: no state found in response url")}}else i.Log.warn("PopupWindow.notifyOpener: no window.opener. Can't complete notification.")},n(t,[{key:"promise",get:function t(){return this._promise}}]),t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.IFrameNavigator=void 0;var n=r(0),i=r(44);e.IFrameNavigator=function(){function t(){!function e(t,r){if(!(t instanceof r))throw new TypeError("Cannot call a class as a function")}(this,t)}return t.prototype.prepare=function t(e){var r=new i.IFrameWindow(e);return Promise.resolve(r)},t.prototype.callback=function t(e){n.Log.debug("IFrameNavigator.callback");try{return i.IFrameWindow.notifyParent(e),Promise.resolve()}catch(t){return Promise.reject(t)}},t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.IFrameWindow=void 0;var n=function(){function t(t,e){for(var r=0;r<e.length;r++){var n=e[r];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,r,n){return r&&t(e.prototype,r),n&&t(e,n),e}}(),i=r(0);e.IFrameWindow=function(){function t(e){var r=this;!function n(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}(this,t),this._promise=new Promise((function(t,e){r._resolve=t,r._reject=e})),this._boundMessageEvent=this._message.bind(this),window.addEventListener("message",this._boundMessageEvent,!1),this._frame=window.document.createElement("iframe"),this._frame.style.visibility="hidden",this._frame.style.position="absolute",this._frame.width=0,this._frame.height=0,window.document.body.appendChild(this._frame)}return t.prototype.navigate=function t(e){if(e&&e.url){var r=e.silentRequestTimeout||1e4;i.Log.debug("IFrameWindow.navigate: Using timeout of:",r),this._timer=window.setTimeout(this._timeout.bind(this),r),this._frame.src=e.url}else this._error("No url provided");return this.promise},t.prototype._success=function t(e){this._cleanup(),i.Log.debug("IFrameWindow: Successful response from frame window"),this._resolve(e)},t.prototype._error=function t(e){this._cleanup(),i.Log.error(e),this._reject(new Error(e))},t.prototype.close=function t(){this._cleanup()},t.prototype._cleanup=function t(){this._frame&&(i.Log.debug("IFrameWindow: cleanup"),window.removeEventListener("message",this._boundMessageEvent,!1),window.clearTimeout(this._timer),window.document.body.removeChild(this._frame),this._timer=null,this._frame=null,this._boundMessageEvent=null)},t.prototype._timeout=function t(){i.Log.debug("IFrameWindow.timeout"),this._error("Frame window timed out")},t.prototype._message=function t(e){if(i.Log.debug("IFrameWindow.message"),this._timer&&e.origin===this._origin&&e.source===this._frame.contentWindow&&"string"==typeof e.data&&(e.data.startsWith("http://")||e.data.startsWith("https://"))){var r=e.data;r?this._success({url:r}):this._error("Invalid response from frame")}},t.notifyParent=function t(e){i.Log.debug("IFrameWindow.notifyParent"),(e=e||window.location.href)&&(i.Log.debug("IFrameWindow.notifyParent: posting url message to parent"),window.parent.postMessage(e,location.protocol+"//"+location.host))},n(t,[{key:"promise",get:function t(){return this._promise}},{key:"_origin",get:function t(){return location.protocol+"//"+location.host}}]),t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.UserManagerEvents=void 0;var n=r(0),i=r(16),o=r(17);e.UserManagerEvents=function(t){function e(r){!function n(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}(this,e);var i=function s(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}(this,t.call(this,r));return i._userLoaded=new o.Event("User loaded"),i._userUnloaded=new o.Event("User unloaded"),i._silentRenewError=new o.Event("Silent renew error"),i._userSignedIn=new o.Event("User signed in"),i._userSignedOut=new o.Event("User signed out"),i._userSessionChanged=new o.Event("User session changed"),i}return function r(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}(e,t),e.prototype.load=function e(r){var i=!(arguments.length>1&&void 0!==arguments[1])||arguments[1];n.Log.debug("UserManagerEvents.load"),t.prototype.load.call(this,r),i&&this._userLoaded.raise(r)},e.prototype.unload=function e(){n.Log.debug("UserManagerEvents.unload"),t.prototype.unload.call(this),this._userUnloaded.raise()},e.prototype.addUserLoaded=function t(e){this._userLoaded.addHandler(e)},e.prototype.removeUserLoaded=function t(e){this._userLoaded.removeHandler(e)},e.prototype.addUserUnloaded=function t(e){this._userUnloaded.addHandler(e)},e.prototype.removeUserUnloaded=function t(e){this._userUnloaded.removeHandler(e)},e.prototype.addSilentRenewError=function t(e){this._silentRenewError.addHandler(e)},e.prototype.removeSilentRenewError=function t(e){this._silentRenewError.removeHandler(e)},e.prototype._raiseSilentRenewError=function t(e){n.Log.debug("UserManagerEvents._raiseSilentRenewError",e.message),this._silentRenewError.raise(e)},e.prototype.addUserSignedIn=function t(e){this._userSignedIn.addHandler(e)},e.prototype.removeUserSignedIn=function t(e){this._userSignedIn.removeHandler(e)},e.prototype._raiseUserSignedIn=function t(){n.Log.debug("UserManagerEvents._raiseUserSignedIn"),this._userSignedIn.raise()},e.prototype.addUserSignedOut=function t(e){this._userSignedOut.addHandler(e)},e.prototype.removeUserSignedOut=function t(e){this._userSignedOut.removeHandler(e)},e.prototype._raiseUserSignedOut=function t(){n.Log.debug("UserManagerEvents._raiseUserSignedOut"),this._userSignedOut.raise()},e.prototype.addUserSessionChanged=function t(e){this._userSessionChanged.addHandler(e)},e.prototype.removeUserSessionChanged=function t(e){this._userSessionChanged.removeHandler(e)},e.prototype._raiseUserSessionChanged=function t(){n.Log.debug("UserManagerEvents._raiseUserSessionChanged"),this._userSessionChanged.raise()},e}(i.AccessTokenEvents)},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.Timer=void 0;var n=function(){function t(t,e){for(var r=0;r<e.length;r++){var n=e[r];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,r,n){return r&&t(e.prototype,r),n&&t(e,n),e}}(),i=r(0),o=r(1),s=r(17);function a(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function u(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}e.Timer=function(t){function e(r){var n=arguments.length>1&&void 0!==arguments[1]?arguments[1]:o.Global.timer,i=arguments.length>2&&void 0!==arguments[2]?arguments[2]:void 0;a(this,e);var s=u(this,t.call(this,r));return s._timer=n,s._nowFunc=i||function(){return Date.now()/1e3},s}return function r(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}(e,t),e.prototype.init=function t(e){e<=0&&(e=1),e=parseInt(e);var r=this.now+e;if(this.expiration===r&&this._timerHandle)i.Log.debug("Timer.init timer "+this._name+" skipping initialization since already initialized for expiration:",this.expiration);else{this.cancel(),i.Log.debug("Timer.init timer "+this._name+" for duration:",e),this._expiration=r;var n=5;e<n&&(n=e),this._timerHandle=this._timer.setInterval(this._callback.bind(this),1e3*n)}},e.prototype.cancel=function t(){this._timerHandle&&(i.Log.debug("Timer.cancel: ",this._name),this._timer.clearInterval(this._timerHandle),this._timerHandle=null)},e.prototype._callback=function e(){var r=this._expiration-this.now;i.Log.debug("Timer.callback; "+this._name+" timer expires in:",r),this._expiration<=this.now&&(this.cancel(),t.prototype.raise.call(this))},n(e,[{key:"now",get:function t(){return parseInt(this._nowFunc())}},{key:"expiration",get:function t(){return this._expiration}}]),e}(s.Event)},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.SilentRenewService=void 0;var n=r(0);e.SilentRenewService=function(){function t(e){!function r(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}(this,t),this._userManager=e}return t.prototype.start=function t(){this._callback||(this._callback=this._tokenExpiring.bind(this),this._userManager.events.addAccessTokenExpiring(this._callback),this._userManager.getUser().then((function(t){})).catch((function(t){n.Log.error("SilentRenewService.start: Error from getUser:",t.message)})))},t.prototype.stop=function t(){this._callback&&(this._userManager.events.removeAccessTokenExpiring(this._callback),delete this._callback)},t.prototype._tokenExpiring=function t(){var e=this;this._userManager.signinSilent().then((function(t){n.Log.debug("SilentRenewService._tokenExpiring: Silent token renewal successful")}),(function(t){n.Log.error("SilentRenewService._tokenExpiring: Error from signinSilent:",t.message),e._userManager.events._raiseSilentRenewError(t)}))},t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.CordovaPopupNavigator=void 0;var n=r(21);e.CordovaPopupNavigator=function(){function t(){!function e(t,r){if(!(t instanceof r))throw new TypeError("Cannot call a class as a function")}(this,t)}return t.prototype.prepare=function t(e){var r=new n.CordovaPopupWindow(e);return Promise.resolve(r)},t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.CordovaIFrameNavigator=void 0;var n=r(21);e.CordovaIFrameNavigator=function(){function t(){!function e(t,r){if(!(t instanceof r))throw new TypeError("Cannot call a class as a function")}(this,t)}return t.prototype.prepare=function t(e){e.popupWindowFeatures="hidden=yes";var r=new n.CordovaPopupWindow(e);return Promise.resolve(r)},t}()},function(t,e,r){"use strict";Object.defineProperty(e,"__esModule",{value:!0});e.Version="1.11.6"}])}));
},{}],3:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const oidc_client_ext_1 = require("@inrupt/oidc-client-ext");
const constant_1 = require("./constant");
const globalFetch = (request, init) => window.fetch(request, init);
class ClientAuthentication {
    constructor(loginHandler, redirectHandler, logoutHandler, sessionInfoManager, issuerConfigFetcher) {
        this.loginHandler = loginHandler;
        this.redirectHandler = redirectHandler;
        this.logoutHandler = logoutHandler;
        this.sessionInfoManager = sessionInfoManager;
        this.issuerConfigFetcher = issuerConfigFetcher;
        this.login = async (options, eventEmitter) => {
            var _a, _b;
            await this.sessionInfoManager.clear(options.sessionId);
            const redirectUrl = (0, oidc_client_ext_1.removeOidcQueryParam)((_a = options.redirectUrl) !== null && _a !== void 0 ? _a : window.location.href);
            await this.loginHandler.handle({
                ...options,
                redirectUrl,
                clientName: (_b = options.clientName) !== null && _b !== void 0 ? _b : options.clientId,
                eventEmitter,
            });
        };
        this.fetch = globalFetch;
        this.logout = async (sessionId) => {
            await this.logoutHandler.handle(sessionId);
            this.fetch = globalFetch;
        };
        this.getSessionInfo = async (sessionId) => {
            return this.sessionInfoManager.get(sessionId);
        };
        this.getAllSessionInfo = async () => {
            return this.sessionInfoManager.getAll();
        };
        this.validateCurrentSession = async () => {
            const currentSessionId = window.localStorage.getItem(constant_1.KEY_CURRENT_SESSION);
            if (currentSessionId === null) {
                return null;
            }
            const sessionInfo = await this.sessionInfoManager.get(currentSessionId);
            if (sessionInfo === undefined ||
                sessionInfo.clientAppId === undefined ||
                sessionInfo.issuer === undefined) {
                return null;
            }
            return sessionInfo;
        };
        this.handleIncomingRedirect = async (url, eventEmitter) => {
            const redirectInfo = await this.redirectHandler.handle(url, eventEmitter);
            this.fetch = redirectInfo.fetch.bind(window);
            const cleanedUpUrl = new URL(url);
            cleanedUpUrl.searchParams.delete("state");
            cleanedUpUrl.searchParams.delete("code");
            cleanedUpUrl.searchParams.delete("id_token");
            cleanedUpUrl.searchParams.delete("access_token");
            cleanedUpUrl.searchParams.delete("error");
            cleanedUpUrl.searchParams.delete("error_description");
            window.history.replaceState(null, "", cleanedUpUrl.toString());
            return {
                isLoggedIn: redirectInfo.isLoggedIn,
                webId: redirectInfo.webId,
                sessionId: redirectInfo.sessionId,
                expirationDate: redirectInfo.expirationDate,
            };
        };
    }
}
exports.default = ClientAuthentication;

},{"./constant":5,"@inrupt/oidc-client-ext":1}],4:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Session = exports.silentlyAuthenticate = void 0;
const events_1 = require("events");
const solid_client_authn_core_1 = require("@inrupt/solid-client-authn-core");
const uuid_1 = require("uuid");
const dependencies_1 = require("./dependencies");
const constant_1 = require("./constant");
const iframe_1 = require("./iframe");
async function silentlyAuthenticate(sessionId, clientAuthn, options = {
    inIframe: false,
}, session) {
    var _a;
    const storedSessionInfo = await clientAuthn.validateCurrentSession();
    if (storedSessionInfo !== null) {
        window.localStorage.setItem(constant_1.KEY_CURRENT_URL, window.location.href);
        await clientAuthn.login({
            sessionId,
            prompt: "none",
            oidcIssuer: storedSessionInfo.issuer,
            redirectUrl: storedSessionInfo.redirectUrl,
            clientId: storedSessionInfo.clientAppId,
            clientSecret: storedSessionInfo.clientAppSecret,
            tokenType: (_a = storedSessionInfo.tokenType) !== null && _a !== void 0 ? _a : "DPoP",
            inIframe: options.inIframe,
        }, session);
        return true;
    }
    return false;
}
exports.silentlyAuthenticate = silentlyAuthenticate;
function isLoggedIn(sessionInfo) {
    return !!(sessionInfo === null || sessionInfo === void 0 ? void 0 : sessionInfo.isLoggedIn);
}
class Session extends events_1.EventEmitter {
    constructor(sessionOptions = {}, sessionId) {
        super();
        this.tokenRequestInProgress = false;
        this.tmpFetchWithCookies = false;
        this.login = async (options) => {
            var _a;
            await this.clientAuthentication.login({
                sessionId: this.info.sessionId,
                ...options,
                tokenType: (_a = options.tokenType) !== null && _a !== void 0 ? _a : "DPoP",
            }, this);
            return new Promise(() => undefined);
        };
        this.fetch = async (url, init) => {
            return this.clientAuthentication.fetch(url, {
                ...init,
                credentials: this.tmpFetchWithCookies
                    ?
                        "include"
                    :
                        init === null || init === void 0 ? void 0 : init.credentials,
            });
        };
        this.logout = async () => {
            await this.clientAuthentication.logout(this.info.sessionId);
            this.info.isLoggedIn = false;
            this.tmpFetchWithCookies = false;
            this.emit("logout");
        };
        this.handleIncomingRedirect = async (inputOptions = {}) => {
            var _a;
            if (this.info.isLoggedIn) {
                return this.info;
            }
            if (this.tokenRequestInProgress) {
                return undefined;
            }
            const options = typeof inputOptions === "string" ? { url: inputOptions } : inputOptions;
            const url = (_a = options.url) !== null && _a !== void 0 ? _a : window.location.href;
            if (window.frameElement !== null) {
                (0, iframe_1.postRedirectUrlToParent)(url);
                return undefined;
            }
            if (options.useEssSession !== true ||
                options.restorePreviousSession === true) {
                window.localStorage.setItem("tmp-resource-server-session-enabled", "false");
            }
            else {
                window.localStorage.setItem("tmp-resource-server-session-enabled", "true");
            }
            const storedSessionCookieReference = window.localStorage.getItem("tmp-resource-server-session-info");
            if (typeof storedSessionCookieReference === "string" &&
                options.restorePreviousSession !== true &&
                options.useEssSession === true) {
                function isValidSessionCookieReference(reference) {
                    var _a;
                    const resourceServers = Object.keys((_a = reference.sessions) !== null && _a !== void 0 ? _a : {});
                    return (typeof reference.webId === "string" &&
                        resourceServers.length > 0 &&
                        typeof reference.sessions[resourceServers[0]].expiration === "number");
                }
                const reference = JSON.parse(storedSessionCookieReference);
                if (isValidSessionCookieReference(reference)) {
                    const resourceServers = Object.keys(reference.sessions);
                    const webIdOrigin = new URL(reference.webId).hostname;
                    const ownResourceServer = resourceServers.find((resourceServer) => {
                        return new URL(resourceServer).hostname === webIdOrigin;
                    });
                    const relevantServer = ownResourceServer !== null && ownResourceServer !== void 0 ? ownResourceServer : resourceServers[0];
                    if (reference.sessions[relevantServer].expiration - Date.now() >
                        5 * 60 * 1000) {
                        this.info.isLoggedIn = true;
                        this.info.webId = reference.webId;
                        this.tmpFetchWithCookies = true;
                        return this.info;
                    }
                }
            }
            this.tokenRequestInProgress = true;
            const sessionInfo = await this.clientAuthentication.handleIncomingRedirect(url, this);
            if (isLoggedIn(sessionInfo)) {
                this.setSessionInfo(sessionInfo);
                const currentUrl = window.localStorage.getItem(constant_1.KEY_CURRENT_URL);
                if (currentUrl === null) {
                    this.emit("login");
                }
                else {
                    window.localStorage.removeItem(constant_1.KEY_CURRENT_URL);
                    this.emit("sessionRestore", currentUrl);
                }
            }
            else if (options.restorePreviousSession === true) {
                const storedSessionId = window.localStorage.getItem(constant_1.KEY_CURRENT_SESSION);
                if (storedSessionId !== null) {
                    const attemptedSilentAuthentication = await silentlyAuthenticate(storedSessionId, this.clientAuthentication, undefined, this);
                    if (attemptedSilentAuthentication) {
                        return new Promise(() => { });
                    }
                }
            }
            this.tokenRequestInProgress = false;
            return sessionInfo;
        };
        if (sessionOptions.clientAuthentication) {
            this.clientAuthentication = sessionOptions.clientAuthentication;
        }
        else if (sessionOptions.secureStorage && sessionOptions.insecureStorage) {
            this.clientAuthentication = (0, dependencies_1.getClientAuthenticationWithDependencies)({
                secureStorage: sessionOptions.secureStorage,
                insecureStorage: sessionOptions.insecureStorage,
            });
        }
        else {
            this.clientAuthentication = (0, dependencies_1.getClientAuthenticationWithDependencies)({});
        }
        if (sessionOptions.sessionInfo) {
            this.info = {
                sessionId: sessionOptions.sessionInfo.sessionId,
                isLoggedIn: false,
                webId: sessionOptions.sessionInfo.webId,
            };
        }
        else {
            this.info = {
                sessionId: sessionId !== null && sessionId !== void 0 ? sessionId : (0, uuid_1.v4)(),
                isLoggedIn: false,
            };
        }
        (0, iframe_1.setupIframeListener)(async (redirectUrl) => {
            const sessionInfo = await this.clientAuthentication.handleIncomingRedirect(redirectUrl, this);
            if (!isLoggedIn(sessionInfo)) {
                return;
            }
            this.setSessionInfo(sessionInfo);
        });
        this.on("tokenRenewal", () => silentlyAuthenticate(this.info.sessionId, this.clientAuthentication, {
            inIframe: true,
        }, this));
    }
    onLogin(callback) {
        this.on("login", callback);
    }
    onLogout(callback) {
        this.on("logout", callback);
    }
    onError(callback) {
        this.on(solid_client_authn_core_1.EVENTS.ERROR, callback);
    }
    onSessionRestore(callback) {
        this.on("sessionRestore", callback);
    }
    onSessionExpiration(callback) {
        this.on(solid_client_authn_core_1.EVENTS.SESSION_EXPIRED, callback);
    }
    setSessionInfo(sessionInfo) {
        this.info.isLoggedIn = sessionInfo.isLoggedIn;
        this.info.webId = sessionInfo.webId;
        this.info.sessionId = sessionInfo.sessionId;
        this.info.expirationDate = sessionInfo.expirationDate;
        this.on(solid_client_authn_core_1.EVENTS.SESSION_EXTENDED, (expiresIn) => {
            this.info.expirationDate = Date.now() + expiresIn * 1000;
        });
    }
}
exports.Session = Session;

},{"./constant":5,"./dependencies":7,"./iframe":8,"@inrupt/solid-client-authn-core":33,"events":46,"uuid":155}],5:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.KEY_CURRENT_URL = exports.KEY_CURRENT_SESSION = void 0;
const solid_client_authn_core_1 = require("@inrupt/solid-client-authn-core");
exports.KEY_CURRENT_SESSION = `${solid_client_authn_core_1.SOLID_CLIENT_AUTHN_KEY_PREFIX}currentSession`;
exports.KEY_CURRENT_URL = `${solid_client_authn_core_1.SOLID_CLIENT_AUTHN_KEY_PREFIX}currentUrl`;

},{"@inrupt/solid-client-authn-core":33}],6:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.onSessionRestore = exports.onLogout = exports.onLogin = exports.handleIncomingRedirect = exports.logout = exports.login = exports.fetch = exports.getDefaultSession = void 0;
const Session_1 = require("./Session");
let defaultSession;
function getDefaultSession() {
    if (typeof defaultSession === "undefined") {
        defaultSession = new Session_1.Session();
    }
    return defaultSession;
}
exports.getDefaultSession = getDefaultSession;
const fetch = (...args) => {
    const session = getDefaultSession();
    return session.fetch(...args);
};
exports.fetch = fetch;
const login = (...args) => {
    const session = getDefaultSession();
    return session.login(...args);
};
exports.login = login;
const logout = (...args) => {
    const session = getDefaultSession();
    return session.logout(...args);
};
exports.logout = logout;
const handleIncomingRedirect = (...args) => {
    const session = getDefaultSession();
    return session.handleIncomingRedirect(...args);
};
exports.handleIncomingRedirect = handleIncomingRedirect;
const onLogin = (...args) => {
    const session = getDefaultSession();
    return session.onLogin(...args);
};
exports.onLogin = onLogin;
const onLogout = (...args) => {
    const session = getDefaultSession();
    return session.onLogout(...args);
};
exports.onLogout = onLogout;
const onSessionRestore = (...args) => {
    const session = getDefaultSession();
    return session.onSessionRestore(...args);
};
exports.onSessionRestore = onSessionRestore;

},{"./Session":4}],7:[function(require,module,exports){
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getClientAuthenticationWithDependencies = void 0;
const solid_client_authn_core_1 = require("@inrupt/solid-client-authn-core");
const StorageUtility_1 = __importDefault(require("./storage/StorageUtility"));
const ClientAuthentication_1 = __importDefault(require("./ClientAuthentication"));
const OidcLoginHandler_1 = __importDefault(require("./login/oidc/OidcLoginHandler"));
const AuthorizationCodeWithPkceOidcHandler_1 = __importDefault(require("./login/oidc/oidcHandlers/AuthorizationCodeWithPkceOidcHandler"));
const IssuerConfigFetcher_1 = __importDefault(require("./login/oidc/IssuerConfigFetcher"));
const FallbackRedirectHandler_1 = require("./login/oidc/redirectHandler/FallbackRedirectHandler");
const GeneralLogoutHandler_1 = __importDefault(require("./logout/GeneralLogoutHandler"));
const SessionInfoManager_1 = require("./sessionInfo/SessionInfoManager");
const AuthCodeRedirectHandler_1 = require("./login/oidc/redirectHandler/AuthCodeRedirectHandler");
const AggregateRedirectHandler_1 = __importDefault(require("./login/oidc/redirectHandler/AggregateRedirectHandler"));
const BrowserStorage_1 = __importDefault(require("./storage/BrowserStorage"));
const Redirector_1 = __importDefault(require("./login/oidc/Redirector"));
const ClientRegistrar_1 = __importDefault(require("./login/oidc/ClientRegistrar"));
const ErrorOidcHandler_1 = require("./login/oidc/redirectHandler/ErrorOidcHandler");
const TokenRefresher_1 = __importDefault(require("./login/oidc/refresh/TokenRefresher"));
function getClientAuthenticationWithDependencies(dependencies) {
    const inMemoryStorage = new solid_client_authn_core_1.InMemoryStorage();
    const secureStorage = dependencies.secureStorage || inMemoryStorage;
    const insecureStorage = dependencies.insecureStorage || new BrowserStorage_1.default();
    const storageUtility = new StorageUtility_1.default(secureStorage, insecureStorage);
    const issuerConfigFetcher = new IssuerConfigFetcher_1.default(storageUtility);
    const clientRegistrar = new ClientRegistrar_1.default(storageUtility);
    const sessionInfoManager = new SessionInfoManager_1.SessionInfoManager(storageUtility);
    const tokenRefresher = new TokenRefresher_1.default(storageUtility, issuerConfigFetcher, clientRegistrar);
    const loginHandler = new OidcLoginHandler_1.default(storageUtility, new AuthorizationCodeWithPkceOidcHandler_1.default(storageUtility, new Redirector_1.default()), issuerConfigFetcher, clientRegistrar);
    const redirectHandler = new AggregateRedirectHandler_1.default([
        new ErrorOidcHandler_1.ErrorOidcHandler(),
        new AuthCodeRedirectHandler_1.AuthCodeRedirectHandler(storageUtility, sessionInfoManager, issuerConfigFetcher, clientRegistrar, tokenRefresher),
        new FallbackRedirectHandler_1.FallbackRedirectHandler(),
    ]);
    return new ClientAuthentication_1.default(loginHandler, redirectHandler, new GeneralLogoutHandler_1.default(sessionInfoManager), sessionInfoManager, issuerConfigFetcher);
}
exports.getClientAuthenticationWithDependencies = getClientAuthenticationWithDependencies;

},{"./ClientAuthentication":3,"./login/oidc/ClientRegistrar":10,"./login/oidc/IssuerConfigFetcher":11,"./login/oidc/OidcLoginHandler":12,"./login/oidc/Redirector":13,"./login/oidc/oidcHandlers/AuthorizationCodeWithPkceOidcHandler":14,"./login/oidc/redirectHandler/AggregateRedirectHandler":15,"./login/oidc/redirectHandler/AuthCodeRedirectHandler":16,"./login/oidc/redirectHandler/ErrorOidcHandler":17,"./login/oidc/redirectHandler/FallbackRedirectHandler":18,"./login/oidc/refresh/TokenRefresher":19,"./logout/GeneralLogoutHandler":20,"./sessionInfo/SessionInfoManager":21,"./storage/BrowserStorage":22,"./storage/StorageUtility":23,"@inrupt/solid-client-authn-core":33}],8:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.postRedirectUrlToParent = exports.setupIframeListener = exports.redirectInIframe = void 0;
let redirectIframe;
function getRedirectIframe() {
    if (typeof redirectIframe === "undefined") {
        redirectIframe = window.document.createElement("iframe");
        redirectIframe.setAttribute("hidden", "true");
        redirectIframe.setAttribute("sandbox", "allow-scripts allow-same-origin");
    }
    return redirectIframe;
}
function redirectInIframe(redirectUrl) {
    const iframe = getRedirectIframe();
    window.document.body.appendChild(iframe);
    iframe.src = redirectUrl;
}
exports.redirectInIframe = redirectInIframe;
function setupIframeListener(handleIframeRedirect) {
    if (typeof window === "undefined") {
        return;
    }
    window.addEventListener("message", async (evt) => {
        const iframe = getRedirectIframe();
        if (evt.origin === window.location.origin &&
            evt.source === iframe.contentWindow) {
            if (typeof evt.data.redirectUrl === "string") {
                await handleIframeRedirect(evt.data.redirectUrl);
            }
        }
        if (window.document.body.contains(iframe)) {
            window.document.body.removeChild(iframe);
        }
    });
}
exports.setupIframeListener = setupIframeListener;
function postRedirectUrlToParent(redirectUrl) {
    window.top.postMessage({
        redirectUrl,
    }, window.location.origin);
}
exports.postRedirectUrlToParent = postRedirectUrlToParent;

},{}],9:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.InMemoryStorage = exports.ConfigurationError = exports.NotImplementedError = exports.getClientAuthenticationWithDependencies = exports.Session = void 0;
var Session_1 = require("./Session");
Object.defineProperty(exports, "Session", { enumerable: true, get: function () { return Session_1.Session; } });
var dependencies_1 = require("./dependencies");
Object.defineProperty(exports, "getClientAuthenticationWithDependencies", { enumerable: true, get: function () { return dependencies_1.getClientAuthenticationWithDependencies; } });
__exportStar(require("./defaultSession"), exports);
var solid_client_authn_core_1 = require("@inrupt/solid-client-authn-core");
Object.defineProperty(exports, "NotImplementedError", { enumerable: true, get: function () { return solid_client_authn_core_1.NotImplementedError; } });
Object.defineProperty(exports, "ConfigurationError", { enumerable: true, get: function () { return solid_client_authn_core_1.ConfigurationError; } });
Object.defineProperty(exports, "InMemoryStorage", { enumerable: true, get: function () { return solid_client_authn_core_1.InMemoryStorage; } });

},{"./Session":4,"./defaultSession":6,"./dependencies":7,"@inrupt/solid-client-authn-core":33}],10:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const oidc_client_ext_1 = require("@inrupt/oidc-client-ext");
class ClientRegistrar {
    constructor(storageUtility) {
        this.storageUtility = storageUtility;
    }
    async getClient(options, issuerConfig) {
        var _a;
        const [storedClientId, storedClientSecret,] = await Promise.all([
            this.storageUtility.getForUser(options.sessionId, "clientId", {
                secure: false,
            }),
            this.storageUtility.getForUser(options.sessionId, "clientSecret", {
                secure: false,
            }),
        ]);
        if (storedClientId) {
            return {
                clientId: storedClientId,
                clientSecret: storedClientSecret,
                clientType: "dynamic",
            };
        }
        const extendedOptions = { ...options };
        extendedOptions.registrationAccessToken =
            (_a = extendedOptions.registrationAccessToken) !== null && _a !== void 0 ? _a : (await this.storageUtility.getForUser(options.sessionId, "registrationAccessToken"));
        try {
            const registeredClient = await (0, oidc_client_ext_1.registerClient)(extendedOptions, issuerConfig);
            const infoToSave = {
                clientId: registeredClient.clientId,
            };
            if (registeredClient.clientSecret) {
                infoToSave.clientSecret = registeredClient.clientSecret;
            }
            if (registeredClient.idTokenSignedResponseAlg) {
                infoToSave.idTokenSignedResponseAlg =
                    registeredClient.idTokenSignedResponseAlg;
            }
            await this.storageUtility.setForUser(extendedOptions.sessionId, infoToSave, {
                secure: false,
            });
            return registeredClient;
        }
        catch (error) {
            throw new Error(`Client registration failed: [${error}]`);
        }
    }
}
exports.default = ClientRegistrar;

},{"@inrupt/oidc-client-ext":1}],11:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.WELL_KNOWN_OPENID_CONFIG = void 0;
const solid_client_authn_core_1 = require("@inrupt/solid-client-authn-core");
const urlPath_1 = require("../../util/urlPath");
exports.WELL_KNOWN_OPENID_CONFIG = ".well-known/openid-configuration";
const issuerConfigKeyMap = {
    issuer: {
        toKey: "issuer",
        convertToUrl: true,
    },
    authorization_endpoint: {
        toKey: "authorizationEndpoint",
        convertToUrl: true,
    },
    token_endpoint: {
        toKey: "tokenEndpoint",
        convertToUrl: true,
    },
    userinfo_endpoint: {
        toKey: "userinfoEndpoint",
        convertToUrl: true,
    },
    jwks_uri: {
        toKey: "jwksUri",
        convertToUrl: true,
    },
    registration_endpoint: {
        toKey: "registrationEndpoint",
        convertToUrl: true,
    },
    scopes_supported: { toKey: "scopesSupported" },
    response_types_supported: { toKey: "responseTypesSupported" },
    response_modes_supported: { toKey: "responseModesSupported" },
    grant_types_supported: { toKey: "grantTypesSupported" },
    acr_values_supported: { toKey: "acrValuesSupported" },
    subject_types_supported: { toKey: "subjectTypesSupported" },
    id_token_signing_alg_values_supported: {
        toKey: "idTokenSigningAlgValuesSupported",
    },
    id_token_encryption_alg_values_supported: {
        toKey: "idTokenEncryptionAlgValuesSupported",
    },
    id_token_encryption_enc_values_supported: {
        toKey: "idTokenEncryptionEncValuesSupported",
    },
    userinfo_signing_alg_values_supported: {
        toKey: "userinfoSigningAlgValuesSupported",
    },
    userinfo_encryption_alg_values_supported: {
        toKey: "userinfoEncryptionAlgValuesSupported",
    },
    userinfo_encryption_enc_values_supported: {
        toKey: "userinfoEncryptionEncValuesSupported",
    },
    request_object_signing_alg_values_supported: {
        toKey: "requestObjectSigningAlgValuesSupported",
    },
    request_object_encryption_alg_values_supported: {
        toKey: "requestObjectEncryptionAlgValuesSupported",
    },
    request_object_encryption_enc_values_supported: {
        toKey: "requestObjectEncryptionEncValuesSupported",
    },
    token_endpoint_auth_methods_supported: {
        toKey: "tokenEndpointAuthMethodsSupported",
    },
    token_endpoint_auth_signing_alg_values_supported: {
        toKey: "tokenEndpointAuthSigningAlgValuesSupported",
    },
    display_values_supported: { toKey: "displayValuesSupported" },
    claim_types_supported: { toKey: "claimTypesSupported" },
    claims_supported: { toKey: "claimsSupported" },
    service_documentation: { toKey: "serviceDocumentation" },
    claims_locales_supported: { toKey: "claimsLocalesSupported" },
    ui_locales_supported: { toKey: "uiLocalesSupported" },
    claims_parameter_supported: { toKey: "claimsParameterSupported" },
    request_parameter_supported: { toKey: "requestParameterSupported" },
    request_uri_parameter_supported: { toKey: "requestUriParameterSupported" },
    require_request_uri_registration: { toKey: "requireRequestUriRegistration" },
    op_policy_uri: {
        toKey: "opPolicyUri",
        convertToUrl: true,
    },
    op_tos_uri: {
        toKey: "opTosUri",
        convertToUrl: true,
    },
    solid_oidc_supported: {
        toKey: "solidOidcSupported",
    },
};
function processConfig(config) {
    const parsedConfig = {};
    Object.keys(config).forEach((key) => {
        if (issuerConfigKeyMap[key]) {
            parsedConfig[issuerConfigKeyMap[key].toKey] = config[key];
        }
    });
    return parsedConfig;
}
class IssuerConfigFetcher {
    constructor(storageUtility) {
        this.storageUtility = storageUtility;
    }
    static getLocalStorageKey(issuer) {
        return `issuerConfig:${issuer}`;
    }
    async fetchConfig(issuer) {
        let issuerConfig;
        const openIdConfigUrl = (0, urlPath_1.appendToUrlPathname)(issuer, exports.WELL_KNOWN_OPENID_CONFIG);
        const issuerConfigRequestBody = await window.fetch(openIdConfigUrl);
        try {
            issuerConfig = processConfig(await issuerConfigRequestBody.json());
        }
        catch (err) {
            throw new solid_client_authn_core_1.ConfigurationError(`[${issuer.toString()}] has an invalid configuration: ${err.message}`);
        }
        await this.storageUtility.set(IssuerConfigFetcher.getLocalStorageKey(issuer), JSON.stringify(issuerConfig));
        return issuerConfig;
    }
}
exports.default = IssuerConfigFetcher;

},{"../../util/urlPath":24,"@inrupt/solid-client-authn-core":33}],12:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const solid_client_authn_core_1 = require("@inrupt/solid-client-authn-core");
function hasIssuer(options) {
    return typeof options.oidcIssuer === "string";
}
function hasRedirectUrl(options) {
    return typeof options.redirectUrl === "string";
}
class OidcLoginHandler {
    constructor(storageUtility, oidcHandler, issuerConfigFetcher, clientRegistrar) {
        this.storageUtility = storageUtility;
        this.oidcHandler = oidcHandler;
        this.issuerConfigFetcher = issuerConfigFetcher;
        this.clientRegistrar = clientRegistrar;
    }
    async canHandle(options) {
        return hasIssuer(options) && hasRedirectUrl(options);
    }
    async handle(options) {
        if (!hasIssuer(options)) {
            throw new solid_client_authn_core_1.ConfigurationError(`OidcLoginHandler requires an OIDC issuer: missing property 'oidcIssuer' in ${JSON.stringify(options)}`);
        }
        if (!hasRedirectUrl(options)) {
            throw new solid_client_authn_core_1.ConfigurationError(`OidcLoginHandler requires a redirect URL: missing property 'redirectUrl' in ${JSON.stringify(options)}`);
        }
        const issuerConfig = await this.issuerConfigFetcher.fetchConfig(options.oidcIssuer);
        const clientRegistration = await (0, solid_client_authn_core_1.handleRegistration)(options, issuerConfig, this.storageUtility, this.clientRegistrar);
        const OidcOptions = {
            issuer: issuerConfig.issuer,
            dpop: options.tokenType.toLowerCase() === "dpop",
            ...options,
            issuerConfiguration: issuerConfig,
            client: clientRegistration,
        };
        return this.oidcHandler.handle(OidcOptions);
    }
}
exports.default = OidcLoginHandler;

},{"@inrupt/solid-client-authn-core":33}],13:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const iframe_1 = require("../../iframe");
class Redirector {
    redirect(redirectUrl, options) {
        if (options && options.handleRedirect) {
            options.handleRedirect(redirectUrl);
        }
        else if (options && options.redirectByReplacingState) {
            window.history.replaceState({}, "", redirectUrl);
        }
        else if (options === null || options === void 0 ? void 0 : options.redirectInIframe) {
            (0, iframe_1.redirectInIframe)(redirectUrl);
        }
        else {
            window.location.href = redirectUrl;
        }
    }
}
exports.default = Redirector;

},{"../../iframe":8}],14:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const oidc_client_ext_1 = require("@inrupt/oidc-client-ext");
class AuthorizationCodeWithPkceOidcHandler {
    constructor(storageUtility, redirector) {
        this.storageUtility = storageUtility;
        this.redirector = redirector;
    }
    async canHandle(oidcLoginOptions) {
        return !!(oidcLoginOptions.issuerConfiguration.grantTypesSupported &&
            oidcLoginOptions.issuerConfiguration.grantTypesSupported.indexOf("authorization_code") > -1);
    }
    async handle(oidcLoginOptions) {
        var _a;
        const oidcOptions = {
            authority: oidcLoginOptions.issuer.toString(),
            client_id: oidcLoginOptions.client.clientId,
            client_secret: oidcLoginOptions.client.clientSecret,
            redirect_uri: oidcLoginOptions.redirectUrl.toString(),
            post_logout_redirect_uri: oidcLoginOptions.redirectUrl.toString(),
            response_type: "code",
            scope: "openid offline_access webid",
            filterProtocolClaims: true,
            loadUserInfo: false,
            code_verifier: true,
            prompt: (_a = oidcLoginOptions.prompt) !== null && _a !== void 0 ? _a : "consent",
        };
        const oidcClientLibrary = new oidc_client_ext_1.OidcClient(oidcOptions);
        const { redirector } = this;
        const storage = this.storageUtility;
        try {
            const signingRequest = await oidcClientLibrary.createSigninRequest();
            await Promise.all([
                storage.setForUser(signingRequest.state._id, {
                    sessionId: oidcLoginOptions.sessionId,
                }),
                storage.setForUser(oidcLoginOptions.sessionId, {
                    codeVerifier: signingRequest.state._code_verifier,
                    issuer: oidcLoginOptions.issuer.toString(),
                    redirectUrl: oidcLoginOptions.redirectUrl,
                    dpop: oidcLoginOptions.dpop ? "true" : "false",
                }),
            ]);
            redirector.redirect(signingRequest.url.toString(), {
                handleRedirect: oidcLoginOptions.handleRedirect,
                redirectInIframe: oidcLoginOptions.inIframe,
            });
        }
        catch (err) {
            console.error(err);
        }
        return undefined;
    }
}
exports.default = AuthorizationCodeWithPkceOidcHandler;

},{"@inrupt/oidc-client-ext":1}],15:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const solid_client_authn_core_1 = require("@inrupt/solid-client-authn-core");
class AggregateRedirectHandler extends solid_client_authn_core_1.AggregateHandler {
    constructor(redirectHandlers) {
        super(redirectHandlers);
    }
}
exports.default = AggregateRedirectHandler;

},{"@inrupt/solid-client-authn-core":33}],16:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthCodeRedirectHandler = exports.DEFAULT_LIFESPAN = void 0;
const solid_client_authn_core_1 = require("@inrupt/solid-client-authn-core");
const oidc_client_ext_1 = require("@inrupt/oidc-client-ext");
const constant_1 = require("../../../constant");
exports.DEFAULT_LIFESPAN = 30 * 60 * 1000;
async function setupResourceServerSession(webId, authenticatedFetch, storageUtility) {
    const webIdAsUrl = new URL(webId);
    const resourceServerIri = webIdAsUrl.origin;
    await authenticatedFetch(webId);
    try {
        const resourceServerResponse = await authenticatedFetch(`${resourceServerIri}/session`);
        if (resourceServerResponse.status === 200) {
            await storageUtility.storeResourceServerSessionInfo(webId, resourceServerIri, Date.now() + exports.DEFAULT_LIFESPAN);
            return;
        }
        await storageUtility.clearResourceServerSessionInfo(resourceServerIri);
    }
    catch (_e) {
        await storageUtility.clearResourceServerSessionInfo(resourceServerIri);
    }
}
class AuthCodeRedirectHandler {
    constructor(storageUtility, sessionInfoManager, issuerConfigFetcher, clientRegistrar, tokerRefresher) {
        this.storageUtility = storageUtility;
        this.sessionInfoManager = sessionInfoManager;
        this.issuerConfigFetcher = issuerConfigFetcher;
        this.clientRegistrar = clientRegistrar;
        this.tokerRefresher = tokerRefresher;
    }
    async canHandle(redirectUrl) {
        try {
            const myUrl = new URL(redirectUrl);
            return (myUrl.searchParams.get("code") !== null &&
                myUrl.searchParams.get("state") !== null);
        }
        catch (e) {
            throw new Error(`[${redirectUrl}] is not a valid URL, and cannot be used as a redirect URL: ${e}`);
        }
    }
    async handle(redirectUrl, eventEmitter) {
        if (!(await this.canHandle(redirectUrl))) {
            throw new Error(`AuthCodeRedirectHandler cannot handle [${redirectUrl}]: it is missing one of [code, state].`);
        }
        const url = new URL(redirectUrl);
        const oauthState = url.searchParams.get("state");
        const storedSessionId = (await this.storageUtility.getForUser(oauthState, "sessionId", {
            errorIfNull: true,
        }));
        const isDpop = (await this.storageUtility.getForUser(storedSessionId, "dpop")) ===
            "true";
        const issuer = (await this.storageUtility.getForUser(storedSessionId, "issuer", { errorIfNull: true }));
        window.localStorage.setItem(constant_1.KEY_CURRENT_SESSION, storedSessionId);
        const issuerConfig = await this.issuerConfigFetcher.fetchConfig(issuer);
        const client = await this.clientRegistrar.getClient({ sessionId: storedSessionId }, issuerConfig);
        let tokens;
        const referenceTime = Date.now();
        if (isDpop) {
            const codeVerifier = (await this.storageUtility.getForUser(storedSessionId, "codeVerifier", { errorIfNull: true }));
            const storedRedirectIri = (await this.storageUtility.getForUser(storedSessionId, "redirectUrl", { errorIfNull: true }));
            tokens = await (0, oidc_client_ext_1.getDpopToken)(issuerConfig, client, {
                grantType: "authorization_code",
                code: url.searchParams.get("code"),
                codeVerifier,
                redirectUrl: storedRedirectIri,
            });
        }
        else {
            tokens = await (0, oidc_client_ext_1.getBearerToken)(url.toString());
        }
        let refreshOptions;
        if (tokens.refreshToken !== undefined) {
            refreshOptions = {
                sessionId: storedSessionId,
                refreshToken: tokens.refreshToken,
                tokenRefresher: this.tokerRefresher,
            };
        }
        const authFetch = await (0, solid_client_authn_core_1.buildAuthenticatedFetch)(fetch, tokens.accessToken, {
            dpopKey: tokens.dpopKey,
            refreshOptions,
            eventEmitter,
            expiresIn: tokens.expiresIn,
        });
        await this.storageUtility.setForUser(storedSessionId, {
            webId: tokens.webId,
            isLoggedIn: "true",
        }, { secure: true });
        url.searchParams.delete("code");
        await this.storageUtility.setForUser(storedSessionId, {
            redirectUrl: url.toString(),
        }, {
            secure: false,
        });
        const essWorkaroundDisabled = window.localStorage.getItem("tmp-resource-server-session-enabled") ===
            "false";
        if (!essWorkaroundDisabled) {
            await setupResourceServerSession(tokens.webId, authFetch, this.storageUtility);
        }
        const sessionInfo = await this.sessionInfoManager.get(storedSessionId);
        if (!sessionInfo) {
            throw new Error(`Could not retrieve session: [${storedSessionId}].`);
        }
        return Object.assign(sessionInfo, {
            fetch: authFetch,
            expirationDate: typeof tokens.expiresIn === "number"
                ? referenceTime + tokens.expiresIn * 1000
                : null,
        });
    }
}
exports.AuthCodeRedirectHandler = AuthCodeRedirectHandler;

},{"../../../constant":5,"@inrupt/oidc-client-ext":1,"@inrupt/solid-client-authn-core":33}],17:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ErrorOidcHandler = void 0;
const solid_client_authn_core_1 = require("@inrupt/solid-client-authn-core");
const SessionInfoManager_1 = require("../../../sessionInfo/SessionInfoManager");
class ErrorOidcHandler {
    async canHandle(redirectUrl) {
        try {
            return new URL(redirectUrl).searchParams.has("error");
        }
        catch (e) {
            throw new Error(`[${redirectUrl}] is not a valid URL, and cannot be used as a redirect URL: ${e}`);
        }
    }
    async handle(redirectUrl, eventEmitter) {
        if (eventEmitter !== undefined) {
            const url = new URL(redirectUrl);
            const errorUrl = url.searchParams.get("error");
            const errorDescriptionUrl = url.searchParams.get("error_description");
            eventEmitter.emit(solid_client_authn_core_1.EVENTS.ERROR, errorUrl, errorDescriptionUrl);
        }
        return (0, SessionInfoManager_1.getUnauthenticatedSession)();
    }
}
exports.ErrorOidcHandler = ErrorOidcHandler;

},{"../../../sessionInfo/SessionInfoManager":21,"@inrupt/solid-client-authn-core":33}],18:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FallbackRedirectHandler = void 0;
const SessionInfoManager_1 = require("../../../sessionInfo/SessionInfoManager");
class FallbackRedirectHandler {
    async canHandle(redirectUrl) {
        try {
            new URL(redirectUrl);
            return true;
        }
        catch (e) {
            throw new Error(`[${redirectUrl}] is not a valid URL, and cannot be used as a redirect URL: ${e}`);
        }
    }
    async handle(_redirectUrl) {
        return (0, SessionInfoManager_1.getUnauthenticatedSession)();
    }
}
exports.FallbackRedirectHandler = FallbackRedirectHandler;

},{"../../../sessionInfo/SessionInfoManager":21}],19:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const solid_client_authn_core_1 = require("@inrupt/solid-client-authn-core");
const oidc_client_ext_1 = require("@inrupt/oidc-client-ext");
class TokenRefresher {
    constructor(storageUtility, issuerConfigFetcher, clientRegistrar) {
        this.storageUtility = storageUtility;
        this.issuerConfigFetcher = issuerConfigFetcher;
        this.clientRegistrar = clientRegistrar;
    }
    async refresh(sessionId, refreshToken, dpopKey, eventEmitter) {
        const oidcContext = await (0, solid_client_authn_core_1.loadOidcContextFromStorage)(sessionId, this.storageUtility, this.issuerConfigFetcher);
        const clientInfo = await this.clientRegistrar.getClient({ sessionId }, oidcContext.issuerConfig);
        if (refreshToken === undefined) {
            throw new Error(`Session [${sessionId}] has no refresh token to allow it to refresh its access token.`);
        }
        if (oidcContext.dpop && dpopKey === undefined) {
            throw new Error(`For session [${sessionId}], the key bound to the DPoP access token must be provided to refresh said access token.`);
        }
        const tokenSet = await (0, oidc_client_ext_1.refresh)(refreshToken, oidcContext.issuerConfig, clientInfo, dpopKey);
        if (tokenSet.refreshToken !== undefined) {
            eventEmitter === null || eventEmitter === void 0 ? void 0 : eventEmitter.emit(solid_client_authn_core_1.EVENTS.NEW_REFRESH_TOKEN, tokenSet.refreshToken);
            await this.storageUtility.setForUser(sessionId, {
                refreshToken: tokenSet.refreshToken,
            });
        }
        return tokenSet;
    }
}
exports.default = TokenRefresher;

},{"@inrupt/oidc-client-ext":1,"@inrupt/solid-client-authn-core":33}],20:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class GeneralLogoutHandler {
    constructor(sessionInfoManager) {
        this.sessionInfoManager = sessionInfoManager;
    }
    async canHandle() {
        return true;
    }
    async handle(userId) {
        await this.sessionInfoManager.clear(userId);
    }
}
exports.default = GeneralLogoutHandler;

},{}],21:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SessionInfoManager = exports.clear = exports.getUnauthenticatedSession = void 0;
const solid_client_authn_core_1 = require("@inrupt/solid-client-authn-core");
const uuid_1 = require("uuid");
const oidc_client_ext_1 = require("@inrupt/oidc-client-ext");
function getUnauthenticatedSession() {
    return {
        isLoggedIn: false,
        sessionId: (0, uuid_1.v4)(),
        fetch,
    };
}
exports.getUnauthenticatedSession = getUnauthenticatedSession;
async function clear(sessionId, storage) {
    const storedSessionCookieReference = await storage.get("tmp-resource-server-session-info");
    const reference = JSON.parse(storedSessionCookieReference !== null && storedSessionCookieReference !== void 0 ? storedSessionCookieReference : "{}");
    const { webId } = reference;
    if (webId !== undefined) {
        const webIdAsUrl = new URL(webId);
        const resourceServerIri = webIdAsUrl.origin;
        await storage.clearResourceServerSessionInfo(resourceServerIri);
    }
    await Promise.all([
        storage.deleteAllUserData(sessionId, { secure: false }),
        storage.deleteAllUserData(sessionId, { secure: true }),
        storage.delete("clientKey", { secure: false }),
    ]);
    await (0, oidc_client_ext_1.clearOidcPersistentStorage)();
}
exports.clear = clear;
class SessionInfoManager {
    constructor(storageUtility) {
        this.storageUtility = storageUtility;
    }
    update(_sessionId, _options) {
        throw new Error("Not Implemented");
    }
    async get(sessionId) {
        var _a;
        const isLoggedIn = await this.storageUtility.getForUser(sessionId, "isLoggedIn", {
            secure: true,
        });
        const webId = await this.storageUtility.getForUser(sessionId, "webId", {
            secure: true,
        });
        const clientId = await this.storageUtility.getForUser(sessionId, "clientId", {
            secure: false,
        });
        const clientSecret = await this.storageUtility.getForUser(sessionId, "clientSecret", {
            secure: false,
        });
        const redirectUrl = await this.storageUtility.getForUser(sessionId, "redirectUrl", {
            secure: false,
        });
        const refreshToken = await this.storageUtility.getForUser(sessionId, "refreshToken", {
            secure: true,
        });
        const issuer = await this.storageUtility.getForUser(sessionId, "issuer", {
            secure: false,
        });
        const tokenType = (_a = (await this.storageUtility.getForUser(sessionId, "tokenType", {
            secure: false,
        }))) !== null && _a !== void 0 ? _a : "DPoP";
        if (!(0, solid_client_authn_core_1.isSupportedTokenType)(tokenType)) {
            throw new Error(`Tokens of type [${tokenType}] are not supported.`);
        }
        if (clientId === undefined &&
            isLoggedIn === undefined &&
            webId === undefined &&
            refreshToken === undefined) {
            return undefined;
        }
        return {
            sessionId,
            webId,
            isLoggedIn: isLoggedIn === "true",
            redirectUrl,
            refreshToken,
            issuer,
            clientAppId: clientId,
            clientAppSecret: clientSecret,
            tokenType,
        };
    }
    async getAll() {
        throw new Error("Not implemented");
    }
    async clear(sessionId) {
        return clear(sessionId, this.storageUtility);
    }
    async register(_sessionId) {
        throw new Error("Not implemented");
    }
    async getRegisteredSessionIdAll() {
        throw new Error("Not implemented");
    }
    async clearAll() {
        throw new Error("Not implemented");
    }
}
exports.SessionInfoManager = SessionInfoManager;

},{"@inrupt/oidc-client-ext":1,"@inrupt/solid-client-authn-core":33,"uuid":155}],22:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class BrowserStorage {
    get storage() {
        return window.localStorage;
    }
    async get(key) {
        return this.storage.getItem(key) || undefined;
    }
    async set(key, value) {
        this.storage.setItem(key, value);
    }
    async delete(key) {
        this.storage.removeItem(key);
    }
}
exports.default = BrowserStorage;

},{}],23:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const solid_client_authn_core_1 = require("@inrupt/solid-client-authn-core");
class StorageUtilityBrowser extends solid_client_authn_core_1.StorageUtility {
    constructor(secureStorage, insecureStorage) {
        super(secureStorage, insecureStorage);
    }
}
exports.default = StorageUtilityBrowser;

},{"@inrupt/solid-client-authn-core":33}],24:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.appendToUrlPathname = void 0;
function appendToUrlPathname(url, append) {
    const parsedUrl = new URL(url);
    const path = parsedUrl.pathname;
    parsedUrl.pathname = `${path}${path.endsWith("/") ? "" : "/"}${append.startsWith("/") ? append.substring(1) : append}`;
    return parsedUrl.toString();
}
exports.appendToUrlPathname = appendToUrlPathname;

},{}],25:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateDpopKeyPair = exports.createDpopHeader = void 0;
const jose_1 = require("jose");
const uuid_1 = require("uuid");
const constant_1 = require("../constant");
function removeHashUsernameAndPassword(audience) {
    const cleanedAudience = new URL(audience);
    cleanedAudience.hash = "";
    cleanedAudience.username = "";
    cleanedAudience.password = "";
    return cleanedAudience.toString();
}
async function createDpopHeader(audience, method, dpopKey) {
    return new jose_1.SignJWT({
        htu: removeHashUsernameAndPassword(audience),
        htm: method.toUpperCase(),
        jti: (0, uuid_1.v4)(),
    })
        .setProtectedHeader({
        alg: constant_1.PREFERRED_SIGNING_ALG[0],
        jwk: dpopKey.publicKey,
        typ: "dpop+jwt",
    })
        .setIssuedAt()
        .sign(dpopKey.privateKey, {});
}
exports.createDpopHeader = createDpopHeader;
async function generateDpopKeyPair() {
    const { privateKey, publicKey } = await (0, jose_1.generateKeyPair)(constant_1.PREFERRED_SIGNING_ALG[0]);
    const dpopKeyPair = {
        privateKey,
        publicKey: await (0, jose_1.exportJWK)(publicKey),
    };
    [dpopKeyPair.publicKey.alg] = constant_1.PREFERRED_SIGNING_ALG;
    return dpopKeyPair;
}
exports.generateDpopKeyPair = generateDpopKeyPair;

},{"../constant":27,"jose":50,"uuid":155}],26:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildAuthenticatedFetch = exports.DEFAULT_EXPIRATION_TIME_SECONDS = void 0;
const cross_fetch_1 = require("cross-fetch");
const constant_1 = require("../constant");
const dpopUtils_1 = require("./dpopUtils");
const OidcProviderError_1 = require("../errors/OidcProviderError");
const InvalidResponseError_1 = require("../errors/InvalidResponseError");
exports.DEFAULT_EXPIRATION_TIME_SECONDS = 600;
function isExpectedAuthError(statusCode) {
    return [401, 403].includes(statusCode);
}
async function buildDpopFetchOptions(targetUrl, authToken, dpopKey, defaultOptions) {
    var _a;
    const headers = new cross_fetch_1.Headers(defaultOptions === null || defaultOptions === void 0 ? void 0 : defaultOptions.headers);
    headers.set("Authorization", `DPoP ${authToken}`);
    headers.set("DPoP", await (0, dpopUtils_1.createDpopHeader)(targetUrl, (_a = defaultOptions === null || defaultOptions === void 0 ? void 0 : defaultOptions.method) !== null && _a !== void 0 ? _a : "get", dpopKey));
    return {
        ...defaultOptions,
        headers,
    };
}
async function buildAuthenticatedHeaders(targetUrl, authToken, dpopKey, defaultOptions) {
    if (dpopKey !== undefined) {
        return buildDpopFetchOptions(targetUrl, authToken, dpopKey, defaultOptions);
    }
    const headers = new cross_fetch_1.Headers(defaultOptions === null || defaultOptions === void 0 ? void 0 : defaultOptions.headers);
    headers.set("Authorization", `Bearer ${authToken}`);
    return {
        ...defaultOptions,
        headers,
    };
}
async function makeAuthenticatedRequest(unauthFetch, accessToken, url, defaultRequestInit, dpopKey) {
    return unauthFetch(url, await buildAuthenticatedHeaders(url.toString(), accessToken, dpopKey, defaultRequestInit));
}
async function refreshAccessToken(refreshOptions, dpopKey, eventEmitter) {
    var _a;
    const tokenSet = await refreshOptions.tokenRefresher.refresh(refreshOptions.sessionId, refreshOptions.refreshToken, dpopKey);
    eventEmitter === null || eventEmitter === void 0 ? void 0 : eventEmitter.emit(constant_1.EVENTS.SESSION_EXTENDED, (_a = tokenSet.expiresIn) !== null && _a !== void 0 ? _a : exports.DEFAULT_EXPIRATION_TIME_SECONDS);
    if (typeof tokenSet.refreshToken === "string") {
        eventEmitter === null || eventEmitter === void 0 ? void 0 : eventEmitter.emit(constant_1.EVENTS.NEW_REFRESH_TOKEN, tokenSet.refreshToken);
    }
    return {
        accessToken: tokenSet.accessToken,
        refreshToken: tokenSet.refreshToken,
        expiresIn: tokenSet.expiresIn,
    };
}
const computeRefreshDelay = (expiresIn) => {
    if (expiresIn !== undefined) {
        return expiresIn - constant_1.REFRESH_BEFORE_EXPIRATION_SECONDS > 0
            ?
                expiresIn - constant_1.REFRESH_BEFORE_EXPIRATION_SECONDS
            : expiresIn;
    }
    return exports.DEFAULT_EXPIRATION_TIME_SECONDS;
};
async function buildAuthenticatedFetch(unauthFetch, accessToken, options) {
    var _a;
    let currentAccessToken = accessToken;
    let latestTimeout;
    const currentRefreshOptions = options === null || options === void 0 ? void 0 : options.refreshOptions;
    if (currentRefreshOptions !== undefined) {
        const proactivelyRefreshToken = async () => {
            var _a, _b, _c, _d;
            try {
                const { accessToken: refreshedAccessToken, refreshToken, expiresIn, } = await refreshAccessToken(currentRefreshOptions, options.dpopKey, options.eventEmitter);
                currentAccessToken = refreshedAccessToken;
                if (refreshToken !== undefined) {
                    currentRefreshOptions.refreshToken = refreshToken;
                }
                clearTimeout(latestTimeout);
                latestTimeout = setTimeout(proactivelyRefreshToken, computeRefreshDelay(expiresIn) * 1000);
                (_a = options.eventEmitter) === null || _a === void 0 ? void 0 : _a.emit(constant_1.EVENTS.TIMEOUT_SET, latestTimeout);
            }
            catch (e) {
                if (e instanceof OidcProviderError_1.OidcProviderError) {
                    (_b = options === null || options === void 0 ? void 0 : options.eventEmitter) === null || _b === void 0 ? void 0 : _b.emit(constant_1.EVENTS.ERROR, e.error, e.errorDescription);
                    (_c = options === null || options === void 0 ? void 0 : options.eventEmitter) === null || _c === void 0 ? void 0 : _c.emit(constant_1.EVENTS.SESSION_EXPIRED);
                }
                if (e instanceof InvalidResponseError_1.InvalidResponseError &&
                    e.missingFields.includes("access_token")) {
                    (_d = options === null || options === void 0 ? void 0 : options.eventEmitter) === null || _d === void 0 ? void 0 : _d.emit(constant_1.EVENTS.SESSION_EXPIRED);
                }
            }
        };
        latestTimeout = setTimeout(proactivelyRefreshToken, computeRefreshDelay(options.expiresIn) * 1000);
        (_a = options.eventEmitter) === null || _a === void 0 ? void 0 : _a.emit(constant_1.EVENTS.TIMEOUT_SET, latestTimeout);
    }
    else if (options !== undefined && options.eventEmitter !== undefined) {
        const expirationTimeout = setTimeout(() => {
            options.eventEmitter.emit(constant_1.EVENTS.SESSION_EXPIRED);
        }, computeRefreshDelay(options.expiresIn) * 1000);
        options.eventEmitter.emit(constant_1.EVENTS.TIMEOUT_SET, expirationTimeout);
    }
    return async (url, requestInit) => {
        let response = await makeAuthenticatedRequest(unauthFetch, currentAccessToken, url, requestInit, options === null || options === void 0 ? void 0 : options.dpopKey);
        const failedButNotExpectedAuthError = !response.ok && !isExpectedAuthError(response.status);
        if (response.ok || failedButNotExpectedAuthError) {
            return response;
        }
        const hasBeenRedirected = response.url !== url;
        if (hasBeenRedirected && (options === null || options === void 0 ? void 0 : options.dpopKey) !== undefined) {
            response = await makeAuthenticatedRequest(unauthFetch, currentAccessToken, response.url, requestInit, options.dpopKey);
        }
        return response;
    };
}
exports.buildAuthenticatedFetch = buildAuthenticatedFetch;

},{"../constant":27,"../errors/InvalidResponseError":30,"../errors/OidcProviderError":32,"./dpopUtils":25,"cross-fetch":45}],27:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.REFRESH_BEFORE_EXPIRATION_SECONDS = exports.EVENTS = exports.PREFERRED_SIGNING_ALG = exports.SOLID_CLIENT_AUTHN_KEY_PREFIX = void 0;
exports.SOLID_CLIENT_AUTHN_KEY_PREFIX = "solidClientAuthn:";
exports.PREFERRED_SIGNING_ALG = ["ES256", "RS256"];
exports.EVENTS = {
    NEW_REFRESH_TOKEN: "newRefreshToken",
    ERROR: "onError",
    SESSION_EXPIRED: "sessionExpired",
    SESSION_EXTENDED: "sessionExtended",
    TIMEOUT_SET: "timeoutSet",
};
exports.REFRESH_BEFORE_EXPIRATION_SECONDS = 5;

},{}],28:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class ConfigurationError extends Error {
    constructor(message) {
        super(message);
    }
}
exports.default = ConfigurationError;

},{}],29:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class InruptError extends Error {
    constructor(messageOrIri, messageParams, appendErrorIri = true) {
        super(typeof messageOrIri === "string"
            ? InruptError.substituteParams(messageOrIri, messageParams)
            : InruptError.appendErrorIri(InruptError.lookupErrorIri(messageOrIri, messageParams), messageOrIri, appendErrorIri));
    }
    httpResponse(httpErrorResponse, appendHttpDetails = true) {
        this.message = InruptError.appendHttpResponseDetails(this.message, httpErrorResponse, appendHttpDetails);
        this.httpErrorResponse = httpErrorResponse;
        return this;
    }
    hasHttpResponse() {
        return this.httpErrorResponse !== undefined;
    }
    getHttpResponse() {
        return this.httpErrorResponse;
    }
    getHttpStatusCode() {
        if (this.httpErrorResponse === undefined) {
            throw new InruptError("This InruptError was not provided with a HTTP response - so we can't get its HTTP Status Code.");
        }
        return this.httpErrorResponse.status;
    }
    getHttpStatusText() {
        if (this.httpErrorResponse === undefined) {
            throw new InruptError("This InruptError was not provided with a HTTP response - so we can't get its HTTP Status Text!");
        }
        return this.httpErrorResponse.statusText;
    }
    static determineIfVocabTerm(value) {
        if (value.strict !== undefined) {
            return true;
        }
        return false;
    }
    static lookupErrorIri(iri, messageParams) {
        if (InruptError.determineIfVocabTerm(iri)) {
            const message = messageParams === undefined
                ? iri.message
                : iri.messageParams(...messageParams);
            return message === undefined
                ? `Looked up error message IRI [${iri.value}], but found no message value.`
                : message;
        }
        return `Error message looked up at: [${iri.value}]${messageParams === undefined
            ? ""
            : `, with params [${messageParams.toString()}]`}`;
    }
    static appendHttpResponseDetails(message, response, append) {
        if (append && typeof response !== "undefined") {
            return `${message} HTTP details: status code [${response.status}], status text [${response.statusText}].`;
        }
        return message;
    }
    static appendErrorIri(message, iri, append) {
        return append ? `${message} Error IRI: [${iri.value}].` : message;
    }
    static substituteParams(message, params) {
        let fullMessage = message;
        if (params !== undefined) {
            const paramsRequired = message.split("{{").length - 1;
            if (paramsRequired !== params.length) {
                throw new Error(`Setting parameters on message [${message}], but it requires [${paramsRequired}] params and we received [${params.length}].`);
            }
            for (let i = 0; i < params.length; i += 1) {
                const marker = `{{${i}}}`;
                fullMessage = fullMessage.replace(marker, params[i]);
            }
        }
        return fullMessage;
    }
}
exports.default = InruptError;

},{}],30:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InvalidResponseError = void 0;
class InvalidResponseError extends Error {
    constructor(missingFields) {
        super(`Invalid response from OIDC provider: missing fields ${missingFields}`);
        this.missingFields = missingFields;
    }
}
exports.InvalidResponseError = InvalidResponseError;

},{}],31:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class NotImplementedError extends Error {
    constructor(methodName) {
        super(`[${methodName}] is not implemented`);
    }
}
exports.default = NotImplementedError;

},{}],32:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OidcProviderError = void 0;
class OidcProviderError extends Error {
    constructor(message, error, errorDescription) {
        super(message);
        this.error = error;
        this.errorDescription = errorDescription;
    }
}
exports.OidcProviderError = OidcProviderError;

},{}],33:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.StorageUtilityGetResponse = exports.StorageUtilityMock = exports.mockStorageUtility = exports.mockStorage = exports.buildAuthenticatedFetch = exports.generateDpopKeyPair = exports.createDpopHeader = exports.OidcProviderError = exports.InvalidResponseError = exports.NotImplementedError = exports.ConfigurationError = exports.InMemoryStorage = exports.getSessionIdFromOauthState = exports.saveSessionInfoToStorage = exports.loadOidcContextFromStorage = exports.StorageUtility = exports.determineSigningAlg = exports.handleRegistration = exports.USER_SESSION_PREFIX = exports.isSupportedTokenType = exports.fetchJwks = exports.getWebidFromTokenPayload = exports.AggregateHandler = void 0;
__exportStar(require("./constant"), exports);
var AggregateHandler_1 = require("./util/handlerPattern/AggregateHandler");
Object.defineProperty(exports, "AggregateHandler", { enumerable: true, get: function () { return __importDefault(AggregateHandler_1).default; } });
var IRedirectHandler_1 = require("./login/oidc/redirectHandler/IRedirectHandler");
Object.defineProperty(exports, "getWebidFromTokenPayload", { enumerable: true, get: function () { return IRedirectHandler_1.getWebidFromTokenPayload; } });
Object.defineProperty(exports, "fetchJwks", { enumerable: true, get: function () { return IRedirectHandler_1.fetchJwks; } });
var ISessionInfo_1 = require("./sessionInfo/ISessionInfo");
Object.defineProperty(exports, "isSupportedTokenType", { enumerable: true, get: function () { return ISessionInfo_1.isSupportedTokenType; } });
var ISessionInfoManager_1 = require("./sessionInfo/ISessionInfoManager");
Object.defineProperty(exports, "USER_SESSION_PREFIX", { enumerable: true, get: function () { return ISessionInfoManager_1.USER_SESSION_PREFIX; } });
var IClientRegistrar_1 = require("./login/oidc/IClientRegistrar");
Object.defineProperty(exports, "handleRegistration", { enumerable: true, get: function () { return IClientRegistrar_1.handleRegistration; } });
Object.defineProperty(exports, "determineSigningAlg", { enumerable: true, get: function () { return IClientRegistrar_1.determineSigningAlg; } });
var StorageUtility_1 = require("./storage/StorageUtility");
Object.defineProperty(exports, "StorageUtility", { enumerable: true, get: function () { return __importDefault(StorageUtility_1).default; } });
Object.defineProperty(exports, "loadOidcContextFromStorage", { enumerable: true, get: function () { return StorageUtility_1.loadOidcContextFromStorage; } });
Object.defineProperty(exports, "saveSessionInfoToStorage", { enumerable: true, get: function () { return StorageUtility_1.saveSessionInfoToStorage; } });
Object.defineProperty(exports, "getSessionIdFromOauthState", { enumerable: true, get: function () { return StorageUtility_1.getSessionIdFromOauthState; } });
var InMemoryStorage_1 = require("./storage/InMemoryStorage");
Object.defineProperty(exports, "InMemoryStorage", { enumerable: true, get: function () { return __importDefault(InMemoryStorage_1).default; } });
var ConfigurationError_1 = require("./errors/ConfigurationError");
Object.defineProperty(exports, "ConfigurationError", { enumerable: true, get: function () { return __importDefault(ConfigurationError_1).default; } });
var NotImplementedError_1 = require("./errors/NotImplementedError");
Object.defineProperty(exports, "NotImplementedError", { enumerable: true, get: function () { return __importDefault(NotImplementedError_1).default; } });
var InvalidResponseError_1 = require("./errors/InvalidResponseError");
Object.defineProperty(exports, "InvalidResponseError", { enumerable: true, get: function () { return InvalidResponseError_1.InvalidResponseError; } });
var OidcProviderError_1 = require("./errors/OidcProviderError");
Object.defineProperty(exports, "OidcProviderError", { enumerable: true, get: function () { return OidcProviderError_1.OidcProviderError; } });
var dpopUtils_1 = require("./authenticatedFetch/dpopUtils");
Object.defineProperty(exports, "createDpopHeader", { enumerable: true, get: function () { return dpopUtils_1.createDpopHeader; } });
Object.defineProperty(exports, "generateDpopKeyPair", { enumerable: true, get: function () { return dpopUtils_1.generateDpopKeyPair; } });
var fetchFactory_1 = require("./authenticatedFetch/fetchFactory");
Object.defineProperty(exports, "buildAuthenticatedFetch", { enumerable: true, get: function () { return fetchFactory_1.buildAuthenticatedFetch; } });
var StorageUtility_2 = require("./storage/__mocks__/StorageUtility");
Object.defineProperty(exports, "mockStorage", { enumerable: true, get: function () { return StorageUtility_2.mockStorage; } });
Object.defineProperty(exports, "mockStorageUtility", { enumerable: true, get: function () { return StorageUtility_2.mockStorageUtility; } });
Object.defineProperty(exports, "StorageUtilityMock", { enumerable: true, get: function () { return StorageUtility_2.StorageUtilityMock; } });
Object.defineProperty(exports, "StorageUtilityGetResponse", { enumerable: true, get: function () { return StorageUtility_2.StorageUtilityGetResponse; } });

},{"./authenticatedFetch/dpopUtils":25,"./authenticatedFetch/fetchFactory":26,"./constant":27,"./errors/ConfigurationError":28,"./errors/InvalidResponseError":30,"./errors/NotImplementedError":31,"./errors/OidcProviderError":32,"./login/oidc/IClientRegistrar":34,"./login/oidc/redirectHandler/IRedirectHandler":35,"./sessionInfo/ISessionInfo":36,"./sessionInfo/ISessionInfoManager":37,"./storage/InMemoryStorage":38,"./storage/StorageUtility":39,"./storage/__mocks__/StorageUtility":40,"./util/handlerPattern/AggregateHandler":41}],34:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.handleRegistration = exports.determineSigningAlg = void 0;
function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    }
    catch (_a) {
        return false;
    }
}
function determineSigningAlg(supported, preferred) {
    var _a;
    return ((_a = preferred.find((signingAlg) => {
        return supported.includes(signingAlg);
    })) !== null && _a !== void 0 ? _a : null);
}
exports.determineSigningAlg = determineSigningAlg;
function determineClientType(options, issuerConfig) {
    if (options.clientId !== undefined && !isValidUrl(options.clientId)) {
        return "static";
    }
    if (issuerConfig.solidOidcSupported ===
        "https://solidproject.org/TR/solid-oidc" &&
        options.clientId !== undefined &&
        isValidUrl(options.clientId)) {
        return "solid-oidc";
    }
    return "dynamic";
}
async function handleRegistration(options, issuerConfig, storageUtility, clientRegistrar) {
    const clientType = determineClientType(options, issuerConfig);
    if (clientType === "dynamic") {
        return clientRegistrar.getClient({
            sessionId: options.sessionId,
            clientName: options.clientName,
            redirectUrl: options.redirectUrl,
        }, issuerConfig);
    }
    await storageUtility.setForUser(options.sessionId, {
        clientId: options.clientId,
    });
    if (options.clientSecret) {
        await storageUtility.setForUser(options.sessionId, {
            clientSecret: options.clientSecret,
        });
    }
    if (options.clientName) {
        await storageUtility.setForUser(options.sessionId, {
            clientName: options.clientName,
        });
    }
    return {
        clientId: options.clientId,
        clientSecret: options.clientSecret,
        clientName: options.clientName,
        clientType,
    };
}
exports.handleRegistration = handleRegistration;

},{}],35:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getWebidFromTokenPayload = exports.fetchJwks = void 0;
const cross_fetch_1 = require("cross-fetch");
const jose_1 = require("jose");
async function fetchJwks(jwksIri, issuerIri) {
    const jwksResponse = await (0, cross_fetch_1.fetch)(jwksIri);
    if (jwksResponse.status !== 200) {
        throw new Error(`Could not fetch JWKS for [${issuerIri}] at [${jwksIri}]: ${jwksResponse.status} ${jwksResponse.statusText}`);
    }
    let jwk;
    try {
        jwk = (await jwksResponse.json()).keys[0];
    }
    catch (e) {
        throw new Error(`Malformed JWKS for [${issuerIri}] at [${jwksIri}]: ${e.message}`);
    }
    return jwk;
}
exports.fetchJwks = fetchJwks;
async function getWebidFromTokenPayload(idToken, jwksIri, issuerIri, clientId) {
    const jwk = await fetchJwks(jwksIri, issuerIri);
    let payload;
    try {
        const { payload: verifiedPayload } = await (0, jose_1.jwtVerify)(idToken, await (0, jose_1.importJWK)(jwk), {
            issuer: issuerIri,
            audience: clientId,
        });
        payload = verifiedPayload;
    }
    catch (e) {
        throw new Error(`ID token verification failed: ${e.stack}`);
    }
    if (typeof payload.webid === "string") {
        return payload.webid;
    }
    if (typeof payload.sub !== "string") {
        throw new Error(`The ID token ${JSON.stringify(payload)} is invalid: it has no 'webid' claim and no 'sub' claim.`);
    }
    try {
        new URL(payload.sub);
        return payload.sub;
    }
    catch (e) {
        throw new Error(`The ID token has no 'webid' claim, and its 'sub' claim of [${payload.sub}] is invalid as a URL - error [${e}].`);
    }
}
exports.getWebidFromTokenPayload = getWebidFromTokenPayload;

},{"cross-fetch":45,"jose":50}],36:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isSupportedTokenType = void 0;
function isSupportedTokenType(token) {
    return typeof token === "string" && ["DPoP", "Bearer"].includes(token);
}
exports.isSupportedTokenType = isSupportedTokenType;

},{}],37:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.USER_SESSION_PREFIX = void 0;
exports.USER_SESSION_PREFIX = "solidClientAuthenticationUser";

},{}],38:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class InMemoryStorage {
    constructor() {
        this.map = {};
    }
    async get(key) {
        return this.map[key] || undefined;
    }
    async set(key, value) {
        this.map[key] = value;
    }
    async delete(key) {
        delete this.map[key];
    }
}
exports.default = InMemoryStorage;

},{}],39:[function(require,module,exports){
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.saveSessionInfoToStorage = exports.loadOidcContextFromStorage = exports.getSessionIdFromOauthState = void 0;
const jose_1 = require("jose");
const InruptError_1 = __importDefault(require("../errors/InruptError"));
async function getSessionIdFromOauthState(storageUtility, oauthState) {
    return storageUtility.getForUser(oauthState, "sessionId");
}
exports.getSessionIdFromOauthState = getSessionIdFromOauthState;
async function loadOidcContextFromStorage(sessionId, storageUtility, configFetcher) {
    try {
        const [issuerIri, codeVerifier, storedRedirectIri, dpop] = await Promise.all([
            storageUtility.getForUser(sessionId, "issuer", {
                errorIfNull: true,
            }),
            storageUtility.getForUser(sessionId, "codeVerifier"),
            storageUtility.getForUser(sessionId, "redirectUrl"),
            storageUtility.getForUser(sessionId, "dpop", { errorIfNull: true }),
        ]);
        const issuerConfig = await configFetcher.fetchConfig(issuerIri);
        return {
            codeVerifier,
            redirectUrl: storedRedirectIri,
            issuerConfig,
            dpop: dpop === "true",
        };
    }
    catch (e) {
        throw new Error(`Failed to retrieve OIDC context from storage associated with session [${sessionId}]: ${e}`);
    }
}
exports.loadOidcContextFromStorage = loadOidcContextFromStorage;
async function saveSessionInfoToStorage(storageUtility, sessionId, webId, isLoggedIn, refreshToken, secure, dpopKey) {
    if (refreshToken !== undefined) {
        await storageUtility.setForUser(sessionId, { refreshToken }, { secure });
    }
    if (webId !== undefined) {
        await storageUtility.setForUser(sessionId, { webId }, { secure });
    }
    if (isLoggedIn !== undefined) {
        await storageUtility.setForUser(sessionId, { isLoggedIn }, { secure });
    }
    if (dpopKey !== undefined) {
        await storageUtility.setForUser(sessionId, {
            publicKey: JSON.stringify(dpopKey.publicKey),
            privateKey: JSON.stringify(await (0, jose_1.exportJWK)(dpopKey.privateKey)),
        }, { secure });
    }
}
exports.saveSessionInfoToStorage = saveSessionInfoToStorage;
class StorageUtility {
    constructor(secureStorage, insecureStorage) {
        this.secureStorage = secureStorage;
        this.insecureStorage = insecureStorage;
        this.RESOURCE_SERVER_SESSION_INFORMATION_KEY = "tmp-resource-server-session-info";
    }
    getKey(userId) {
        return `solidClientAuthenticationUser:${userId}`;
    }
    async getUserData(userId, secure) {
        const stored = await (secure
            ? this.secureStorage
            : this.insecureStorage).get(this.getKey(userId));
        if (stored === undefined) {
            return {};
        }
        try {
            return JSON.parse(stored);
        }
        catch (err) {
            throw new InruptError_1.default(`Data for user [${userId}] in [${secure ? "secure" : "unsecure"}] storage is corrupted - expected valid JSON, but got: ${stored}`);
        }
    }
    async setUserData(userId, data, secure) {
        await (secure ? this.secureStorage : this.insecureStorage).set(this.getKey(userId), JSON.stringify(data));
    }
    async get(key, options) {
        const value = await ((options === null || options === void 0 ? void 0 : options.secure)
            ? this.secureStorage
            : this.insecureStorage).get(key);
        if (value === undefined && (options === null || options === void 0 ? void 0 : options.errorIfNull)) {
            throw new InruptError_1.default(`[${key}] is not stored`);
        }
        return value;
    }
    async set(key, value, options) {
        return ((options === null || options === void 0 ? void 0 : options.secure) ? this.secureStorage : this.insecureStorage).set(key, value);
    }
    async delete(key, options) {
        return ((options === null || options === void 0 ? void 0 : options.secure) ? this.secureStorage : this.insecureStorage).delete(key);
    }
    async getForUser(userId, key, options) {
        const userData = await this.getUserData(userId, options === null || options === void 0 ? void 0 : options.secure);
        let value;
        if (!userData || !userData[key]) {
            value = undefined;
        }
        value = userData[key];
        if (value === undefined && (options === null || options === void 0 ? void 0 : options.errorIfNull)) {
            throw new InruptError_1.default(`Field [${key}] for user [${userId}] is not stored`);
        }
        return value || undefined;
    }
    async setForUser(userId, values, options) {
        let userData;
        try {
            userData = await this.getUserData(userId, options === null || options === void 0 ? void 0 : options.secure);
        }
        catch (_a) {
            userData = {};
        }
        await this.setUserData(userId, { ...userData, ...values }, options === null || options === void 0 ? void 0 : options.secure);
    }
    async deleteForUser(userId, key, options) {
        const userData = await this.getUserData(userId, options === null || options === void 0 ? void 0 : options.secure);
        delete userData[key];
        await this.setUserData(userId, userData, options === null || options === void 0 ? void 0 : options.secure);
    }
    async deleteAllUserData(userId, options) {
        await ((options === null || options === void 0 ? void 0 : options.secure) ? this.secureStorage : this.insecureStorage).delete(this.getKey(userId));
    }
    async storeResourceServerSessionInfo(webId, resourceServerIri, expiration) {
        var _a;
        const sessions = JSON.parse((_a = (await this.insecureStorage.get(this.RESOURCE_SERVER_SESSION_INFORMATION_KEY))) !== null && _a !== void 0 ? _a : "{}");
        if (sessions.webId !== webId) {
            sessions.sessions = {};
        }
        sessions.webId = webId;
        sessions.sessions[resourceServerIri] = {
            expiration,
        };
        await this.insecureStorage.set(this.RESOURCE_SERVER_SESSION_INFORMATION_KEY, JSON.stringify(sessions));
    }
    async clearResourceServerSessionInfo(resourceServerIri) {
        var _a;
        const sessions = JSON.parse((_a = (await this.insecureStorage.get(this.RESOURCE_SERVER_SESSION_INFORMATION_KEY))) !== null && _a !== void 0 ? _a : "{}");
        if (sessions.sessions !== undefined) {
            delete sessions.sessions[resourceServerIri];
            if (Object.keys(sessions.sessions).length === 0) {
                await this.insecureStorage.set(this.RESOURCE_SERVER_SESSION_INFORMATION_KEY, "{}");
            }
            else {
                await this.insecureStorage.set(this.RESOURCE_SERVER_SESSION_INFORMATION_KEY, JSON.stringify(sessions));
            }
        }
    }
}
exports.default = StorageUtility;

},{"../errors/InruptError":29,"jose":50}],40:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.mockStorageUtility = exports.mockStorage = exports.StorageUtilityMock = exports.StorageUtilityGetResponse = void 0;
const __1 = require("../..");
exports.StorageUtilityGetResponse = "getResponse";
exports.StorageUtilityMock = {
    get: async (key, options) => exports.StorageUtilityGetResponse,
    set: async (key, value) => {
    },
    delete: async (key) => {
    },
    getForUser: async (userId, key, options) => exports.StorageUtilityGetResponse,
    setForUser: async (userId, values, options) => {
    },
    deleteForUser: async (userId, key, options) => {
    },
    deleteAllUserData: async (userId, options) => {
    },
    storeResourceServerSessionInfo: async (_webId, _resourceServerIri, _sessionExpires) => {
    },
    clearResourceServerSessionInfo: async (_resourceServerIri) => {
    },
};
const mockStorage = (stored) => {
    const store = stored;
    return {
        get: async (key) => {
            if (store[key] === undefined) {
                return undefined;
            }
            if (typeof store[key] === "string") {
                return store[key];
            }
            return JSON.stringify(store[key]);
        },
        set: async (key, value) => {
            store[key] = value;
        },
        delete: async (key) => {
            delete store[key];
        },
    };
};
exports.mockStorage = mockStorage;
const mockStorageUtility = (stored, isSecure = false) => {
    if (isSecure) {
        return new __1.StorageUtility((0, exports.mockStorage)(stored), (0, exports.mockStorage)({}));
    }
    return new __1.StorageUtility((0, exports.mockStorage)({}), (0, exports.mockStorage)(stored));
};
exports.mockStorageUtility = mockStorageUtility;

},{"../..":33}],41:[function(require,module,exports){
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const InruptError_1 = __importDefault(require("../../errors/InruptError"));
class AggregateHandler {
    constructor(handleables) {
        this.handleables = handleables;
    }
    async getProperHandler(params) {
        const canHandleList = await Promise.all(this.handleables.map((handleable) => handleable.canHandle(...params)));
        for (let i = 0; i < canHandleList.length; i += 1) {
            if (canHandleList[i]) {
                return this.handleables[i];
            }
        }
        return null;
    }
    async canHandle(...params) {
        return (await this.getProperHandler(params)) !== null;
    }
    async handle(...params) {
        const handler = await this.getProperHandler(params);
        if (handler) {
            return handler.handle(...params);
        }
        throw new InruptError_1.default(`[${this.constructor.name}] cannot find a suitable handler for: ${params
            .map((param) => {
            try {
                return JSON.stringify(param);
            }
            catch (err) {
                return param.toString();
            }
        })
            .join(", ")}`);
    }
}
exports.default = AggregateHandler;

},{"../../errors/InruptError":29}],42:[function(require,module,exports){
'use strict'

exports.byteLength = byteLength
exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

var lookup = []
var revLookup = []
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for (var i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i]
  revLookup[code.charCodeAt(i)] = i
}

// Support decoding URL-safe base64 strings, as Node.js does.
// See: https://en.wikipedia.org/wiki/Base64#URL_applications
revLookup['-'.charCodeAt(0)] = 62
revLookup['_'.charCodeAt(0)] = 63

function getLens (b64) {
  var len = b64.length

  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // Trim off extra bytes after placeholder bytes are found
  // See: https://github.com/beatgammit/base64-js/issues/42
  var validLen = b64.indexOf('=')
  if (validLen === -1) validLen = len

  var placeHoldersLen = validLen === len
    ? 0
    : 4 - (validLen % 4)

  return [validLen, placeHoldersLen]
}

// base64 is 4/3 + up to two characters of the original data
function byteLength (b64) {
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function _byteLength (b64, validLen, placeHoldersLen) {
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function toByteArray (b64) {
  var tmp
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]

  var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen))

  var curByte = 0

  // if there are placeholders, only get up to the last complete 4 chars
  var len = placeHoldersLen > 0
    ? validLen - 4
    : validLen

  var i
  for (i = 0; i < len; i += 4) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 18) |
      (revLookup[b64.charCodeAt(i + 1)] << 12) |
      (revLookup[b64.charCodeAt(i + 2)] << 6) |
      revLookup[b64.charCodeAt(i + 3)]
    arr[curByte++] = (tmp >> 16) & 0xFF
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 2) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 2) |
      (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 1) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 10) |
      (revLookup[b64.charCodeAt(i + 1)] << 4) |
      (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] +
    lookup[num >> 12 & 0x3F] +
    lookup[num >> 6 & 0x3F] +
    lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  var tmp
  var output = []
  for (var i = start; i < end; i += 3) {
    tmp =
      ((uint8[i] << 16) & 0xFF0000) +
      ((uint8[i + 1] << 8) & 0xFF00) +
      (uint8[i + 2] & 0xFF)
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

function fromByteArray (uint8) {
  var tmp
  var len = uint8.length
  var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  var parts = []
  var maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1]
    parts.push(
      lookup[tmp >> 2] +
      lookup[(tmp << 4) & 0x3F] +
      '=='
    )
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + uint8[len - 1]
    parts.push(
      lookup[tmp >> 10] +
      lookup[(tmp >> 4) & 0x3F] +
      lookup[(tmp << 2) & 0x3F] +
      '='
    )
  }

  return parts.join('')
}

},{}],43:[function(require,module,exports){

},{}],44:[function(require,module,exports){
(function (Buffer){(function (){
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */

'use strict'

var base64 = require('base64-js')
var ieee754 = require('ieee754')

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

var K_MAX_LENGTH = 0x7fffffff
exports.kMaxLength = K_MAX_LENGTH

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Print warning and recommend using `buffer` v4.x which has an Object
 *               implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * We report that the browser does not support typed arrays if the are not subclassable
 * using __proto__. Firefox 4-29 lacks support for adding new properties to `Uint8Array`
 * (See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438). IE 10 lacks support
 * for __proto__ and has a buggy typed array implementation.
 */
Buffer.TYPED_ARRAY_SUPPORT = typedArraySupport()

if (!Buffer.TYPED_ARRAY_SUPPORT && typeof console !== 'undefined' &&
    typeof console.error === 'function') {
  console.error(
    'This browser lacks typed array (Uint8Array) support which is required by ' +
    '`buffer` v5.x. Use `buffer` v4.x if you require old browser support.'
  )
}

function typedArraySupport () {
  // Can typed array instances can be augmented?
  try {
    var arr = new Uint8Array(1)
    arr.__proto__ = { __proto__: Uint8Array.prototype, foo: function () { return 42 } }
    return arr.foo() === 42
  } catch (e) {
    return false
  }
}

Object.defineProperty(Buffer.prototype, 'parent', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.buffer
  }
})

Object.defineProperty(Buffer.prototype, 'offset', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.byteOffset
  }
})

function createBuffer (length) {
  if (length > K_MAX_LENGTH) {
    throw new RangeError('The value "' + length + '" is invalid for option "size"')
  }
  // Return an augmented `Uint8Array` instance
  var buf = new Uint8Array(length)
  buf.__proto__ = Buffer.prototype
  return buf
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new TypeError(
        'The "string" argument must be of type string. Received type number'
      )
    }
    return allocUnsafe(arg)
  }
  return from(arg, encodingOrOffset, length)
}

// Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
if (typeof Symbol !== 'undefined' && Symbol.species != null &&
    Buffer[Symbol.species] === Buffer) {
  Object.defineProperty(Buffer, Symbol.species, {
    value: null,
    configurable: true,
    enumerable: false,
    writable: false
  })
}

Buffer.poolSize = 8192 // not used by this implementation

function from (value, encodingOrOffset, length) {
  if (typeof value === 'string') {
    return fromString(value, encodingOrOffset)
  }

  if (ArrayBuffer.isView(value)) {
    return fromArrayLike(value)
  }

  if (value == null) {
    throw TypeError(
      'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
      'or Array-like Object. Received type ' + (typeof value)
    )
  }

  if (isInstance(value, ArrayBuffer) ||
      (value && isInstance(value.buffer, ArrayBuffer))) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof value === 'number') {
    throw new TypeError(
      'The "value" argument must not be of type number. Received type number'
    )
  }

  var valueOf = value.valueOf && value.valueOf()
  if (valueOf != null && valueOf !== value) {
    return Buffer.from(valueOf, encodingOrOffset, length)
  }

  var b = fromObject(value)
  if (b) return b

  if (typeof Symbol !== 'undefined' && Symbol.toPrimitive != null &&
      typeof value[Symbol.toPrimitive] === 'function') {
    return Buffer.from(
      value[Symbol.toPrimitive]('string'), encodingOrOffset, length
    )
  }

  throw new TypeError(
    'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
    'or Array-like Object. Received type ' + (typeof value)
  )
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(value, encodingOrOffset, length)
}

// Note: Change prototype *after* Buffer.from is defined to workaround Chrome bug:
// https://github.com/feross/buffer/pull/148
Buffer.prototype.__proto__ = Uint8Array.prototype
Buffer.__proto__ = Uint8Array

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be of type number')
  } else if (size < 0) {
    throw new RangeError('The value "' + size + '" is invalid for option "size"')
  }
}

function alloc (size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpretted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(size).fill(fill, encoding)
      : createBuffer(size).fill(fill)
  }
  return createBuffer(size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(size, fill, encoding)
}

function allocUnsafe (size) {
  assertSize(size)
  return createBuffer(size < 0 ? 0 : checked(size) | 0)
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(size)
}

function fromString (string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('Unknown encoding: ' + encoding)
  }

  var length = byteLength(string, encoding) | 0
  var buf = createBuffer(length)

  var actual = buf.write(string, encoding)

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    buf = buf.slice(0, actual)
  }

  return buf
}

function fromArrayLike (array) {
  var length = array.length < 0 ? 0 : checked(array.length) | 0
  var buf = createBuffer(length)
  for (var i = 0; i < length; i += 1) {
    buf[i] = array[i] & 255
  }
  return buf
}

function fromArrayBuffer (array, byteOffset, length) {
  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('"offset" is outside of buffer bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('"length" is outside of buffer bounds')
  }

  var buf
  if (byteOffset === undefined && length === undefined) {
    buf = new Uint8Array(array)
  } else if (length === undefined) {
    buf = new Uint8Array(array, byteOffset)
  } else {
    buf = new Uint8Array(array, byteOffset, length)
  }

  // Return an augmented `Uint8Array` instance
  buf.__proto__ = Buffer.prototype
  return buf
}

function fromObject (obj) {
  if (Buffer.isBuffer(obj)) {
    var len = checked(obj.length) | 0
    var buf = createBuffer(len)

    if (buf.length === 0) {
      return buf
    }

    obj.copy(buf, 0, 0, len)
    return buf
  }

  if (obj.length !== undefined) {
    if (typeof obj.length !== 'number' || numberIsNaN(obj.length)) {
      return createBuffer(0)
    }
    return fromArrayLike(obj)
  }

  if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
    return fromArrayLike(obj.data)
  }
}

function checked (length) {
  // Note: cannot use `length < K_MAX_LENGTH` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= K_MAX_LENGTH) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + K_MAX_LENGTH.toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return b != null && b._isBuffer === true &&
    b !== Buffer.prototype // so Buffer.isBuffer(Buffer.prototype) will be false
}

Buffer.compare = function compare (a, b) {
  if (isInstance(a, Uint8Array)) a = Buffer.from(a, a.offset, a.byteLength)
  if (isInstance(b, Uint8Array)) b = Buffer.from(b, b.offset, b.byteLength)
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError(
      'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
    )
  }

  if (a === b) return 0

  var x = a.length
  var y = b.length

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!Array.isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  var i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; ++i) {
      length += list[i].length
    }
  }

  var buffer = Buffer.allocUnsafe(length)
  var pos = 0
  for (i = 0; i < list.length; ++i) {
    var buf = list[i]
    if (isInstance(buf, Uint8Array)) {
      buf = Buffer.from(buf)
    }
    if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    }
    buf.copy(buffer, pos)
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (ArrayBuffer.isView(string) || isInstance(string, ArrayBuffer)) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    throw new TypeError(
      'The "string" argument must be one of type string, Buffer, or ArrayBuffer. ' +
      'Received type ' + typeof string
    )
  }

  var len = string.length
  var mustMatch = (arguments.length > 2 && arguments[2] === true)
  if (!mustMatch && len === 0) return 0

  // Use a for loop to avoid recursion
  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len
      case 'utf8':
      case 'utf-8':
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) {
          return mustMatch ? -1 : utf8ToBytes(string).length // assume utf8
        }
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  var loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coersion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// This property is used by `Buffer.isBuffer` (and the `is-buffer` npm package)
// to detect a Buffer instance. It's not possible to use `instanceof Buffer`
// reliably in a browserify context because there could be multiple different
// copies of the 'buffer' package in use. This method works even for Buffer
// instances that were created from another copy of the `buffer` package.
// See: https://github.com/feross/buffer/issues/154
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  var i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  var len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (var i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  var len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (var i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.swap64 = function swap64 () {
  var len = this.length
  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits')
  }
  for (var i = 0; i < len; i += 8) {
    swap(this, i, i + 7)
    swap(this, i + 1, i + 6)
    swap(this, i + 2, i + 5)
    swap(this, i + 3, i + 4)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  var length = this.length
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.toLocaleString = Buffer.prototype.toString

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  var str = ''
  var max = exports.INSPECT_MAX_BYTES
  str = this.toString('hex', 0, max).replace(/(.{2})/g, '$1 ').trim()
  if (this.length > max) str += ' ... '
  return '<Buffer ' + str + '>'
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (isInstance(target, Uint8Array)) {
    target = Buffer.from(target, target.offset, target.byteLength)
  }
  if (!Buffer.isBuffer(target)) {
    throw new TypeError(
      'The "target" argument must be one of type Buffer or Uint8Array. ' +
      'Received type ' + (typeof target)
    )
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  var x = thisEnd - thisStart
  var y = end - start
  var len = Math.min(x, y)

  var thisCopy = this.slice(thisStart, thisEnd)
  var targetCopy = target.slice(start, end)

  for (var i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

// Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf
function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset = +byteOffset // Coerce to Number.
  if (numberIsNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : (buffer.length - 1)
  }

  // Normalize byteOffset: negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset
  if (byteOffset >= buffer.length) {
    if (dir) return -1
    else byteOffset = buffer.length - 1
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0
    else return -1
  }

  // Normalize val
  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  // Finally, search either indexOf (if dir is true) or lastIndexOf
  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
  } else if (typeof val === 'number') {
    val = val & 0xFF // Search for a byte value [0-255]
    if (typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
      }
    }
    return arrayIndexOf(buffer, [ val ], byteOffset, encoding, dir)
  }

  throw new TypeError('val must be string, number or Buffer')
}

function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
  var indexSize = 1
  var arrLength = arr.length
  var valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  var i
  if (dir) {
    var foundIndex = -1
    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
    for (i = byteOffset; i >= 0; i--) {
      var found = true
      for (var j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false
          break
        }
      }
      if (found) return i
    }
  }

  return -1
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
}

Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  var remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  var strLen = string.length

  if (length > strLen / 2) {
    length = strLen / 2
  }
  for (var i = 0; i < length; ++i) {
    var parsed = parseInt(string.substr(i * 2, 2), 16)
    if (numberIsNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function latin1Write (buf, string, offset, length) {
  return asciiWrite(buf, string, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset >>> 0
    if (isFinite(length)) {
      length = length >>> 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  var remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
        return asciiWrite(this, string, offset, length)

      case 'latin1':
      case 'binary':
        return latin1Write(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  var res = []

  var i = start
  while (i < end) {
    var firstByte = buf[i]
    var codePoint = null
    var bytesPerSequence = (firstByte > 0xEF) ? 4
      : (firstByte > 0xDF) ? 3
        : (firstByte > 0xBF) ? 2
          : 1

    if (i + bytesPerSequence <= end) {
      var secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
var MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  var len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  var res = ''
  var i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function latin1Slice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  var len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  var out = ''
  for (var i = start; i < end; ++i) {
    out += toHex(buf[i])
  }
  return out
}

function utf16leSlice (buf, start, end) {
  var bytes = buf.slice(start, end)
  var res = ''
  for (var i = 0; i < bytes.length; i += 2) {
    res += String.fromCharCode(bytes[i] + (bytes[i + 1] * 256))
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  var len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  var newBuf = this.subarray(start, end)
  // Return an augmented `Uint8Array` instance
  newBuf.__proto__ = Buffer.prototype
  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  var val = this[offset + --byteLength]
  var mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var i = byteLength
  var mul = 1
  var val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var mul = 1
  var i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var i = byteLength - 1
  var mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset + 3] = (value >>> 24)
  this[offset + 2] = (value >>> 16)
  this[offset + 1] = (value >>> 8)
  this[offset] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = 0
  var mul = 1
  var sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = byteLength - 1
  var mul = 1
  var sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  this[offset + 2] = (value >>> 16)
  this[offset + 3] = (value >>> 24)
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!Buffer.isBuffer(target)) throw new TypeError('argument should be a Buffer')
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('Index out of range')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  var len = end - start

  if (this === target && typeof Uint8Array.prototype.copyWithin === 'function') {
    // Use built-in when available, missing from IE11
    this.copyWithin(targetStart, start, end)
  } else if (this === target && start < targetStart && targetStart < end) {
    // descending copy from end
    for (var i = len - 1; i >= 0; --i) {
      target[i + targetStart] = this[i + start]
    }
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, end),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
    if (val.length === 1) {
      var code = val.charCodeAt(0)
      if ((encoding === 'utf8' && code < 128) ||
          encoding === 'latin1') {
        // Fast path: If `val` fits into a single byte, use that numeric value.
        val = code
      }
    }
  } else if (typeof val === 'number') {
    val = val & 255
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  var i
  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val
    }
  } else {
    var bytes = Buffer.isBuffer(val)
      ? val
      : Buffer.from(val, encoding)
    var len = bytes.length
    if (len === 0) {
      throw new TypeError('The value "' + val +
        '" is invalid for argument "value"')
    }
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// HELPER FUNCTIONS
// ================

var INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node takes equal signs as end of the Base64 encoding
  str = str.split('=')[0]
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = str.trim().replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function toHex (n) {
  if (n < 16) return '0' + n.toString(16)
  return n.toString(16)
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  var codePoint
  var length = string.length
  var leadSurrogate = null
  var bytes = []

  for (var i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  var c, hi, lo
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  for (var i = 0; i < length; ++i) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

// ArrayBuffer or Uint8Array objects from other contexts (i.e. iframes) do not pass
// the `instanceof` check but they should be treated as of that type.
// See: https://github.com/feross/buffer/issues/166
function isInstance (obj, type) {
  return obj instanceof type ||
    (obj != null && obj.constructor != null && obj.constructor.name != null &&
      obj.constructor.name === type.name)
}
function numberIsNaN (obj) {
  // For IE11 support
  return obj !== obj // eslint-disable-line no-self-compare
}

}).call(this)}).call(this,require("buffer").Buffer)
},{"base64-js":42,"buffer":44,"ieee754":48}],45:[function(require,module,exports){
"use strict";

var global = typeof self !== 'undefined' ? self : void 0;

var __self__ = function () {
  function F() {
    this.fetch = false;
    this.DOMException = global.DOMException;
  }

  F.prototype = global;
  return new F();
}();

(function (self) {
  var irrelevant = function (exports) {
    var support = {
      searchParams: 'URLSearchParams' in self,
      iterable: 'Symbol' in self && 'iterator' in Symbol,
      blob: 'FileReader' in self && 'Blob' in self && function () {
        try {
          new Blob();
          return true;
        } catch (e) {
          return false;
        }
      }(),
      formData: 'FormData' in self,
      arrayBuffer: 'ArrayBuffer' in self
    };

    function isDataView(obj) {
      return obj && DataView.prototype.isPrototypeOf(obj);
    }

    if (support.arrayBuffer) {
      var viewClasses = ['[object Int8Array]', '[object Uint8Array]', '[object Uint8ClampedArray]', '[object Int16Array]', '[object Uint16Array]', '[object Int32Array]', '[object Uint32Array]', '[object Float32Array]', '[object Float64Array]'];

      var isArrayBufferView = ArrayBuffer.isView || function (obj) {
        return obj && viewClasses.indexOf(Object.prototype.toString.call(obj)) > -1;
      };
    }

    function normalizeName(name) {
      if (typeof name !== 'string') {
        name = String(name);
      }

      if (/[^a-z0-9\-#$%&'*+.^_`|~]/i.test(name)) {
        throw new TypeError('Invalid character in header field name');
      }

      return name.toLowerCase();
    }

    function normalizeValue(value) {
      if (typeof value !== 'string') {
        value = String(value);
      }

      return value;
    } // Build a destructive iterator for the value list


    function iteratorFor(items) {
      var iterator = {
        next: function () {
          var value = items.shift();
          return {
            done: value === undefined,
            value: value
          };
        }
      };

      if (support.iterable) {
        iterator[Symbol.iterator] = function () {
          return iterator;
        };
      }

      return iterator;
    }

    function Headers(headers) {
      this.map = {};

      if (headers instanceof Headers) {
        headers.forEach(function (value, name) {
          this.append(name, value);
        }, this);
      } else if (Array.isArray(headers)) {
        headers.forEach(function (header) {
          this.append(header[0], header[1]);
        }, this);
      } else if (headers) {
        Object.getOwnPropertyNames(headers).forEach(function (name) {
          this.append(name, headers[name]);
        }, this);
      }
    }

    Headers.prototype.append = function (name, value) {
      name = normalizeName(name);
      value = normalizeValue(value);
      var oldValue = this.map[name];
      this.map[name] = oldValue ? oldValue + ', ' + value : value;
    };

    Headers.prototype['delete'] = function (name) {
      delete this.map[normalizeName(name)];
    };

    Headers.prototype.get = function (name) {
      name = normalizeName(name);
      return this.has(name) ? this.map[name] : null;
    };

    Headers.prototype.has = function (name) {
      return this.map.hasOwnProperty(normalizeName(name));
    };

    Headers.prototype.set = function (name, value) {
      this.map[normalizeName(name)] = normalizeValue(value);
    };

    Headers.prototype.forEach = function (callback, thisArg) {
      for (var name in this.map) {
        if (this.map.hasOwnProperty(name)) {
          callback.call(thisArg, this.map[name], name, this);
        }
      }
    };

    Headers.prototype.keys = function () {
      var items = [];
      this.forEach(function (value, name) {
        items.push(name);
      });
      return iteratorFor(items);
    };

    Headers.prototype.values = function () {
      var items = [];
      this.forEach(function (value) {
        items.push(value);
      });
      return iteratorFor(items);
    };

    Headers.prototype.entries = function () {
      var items = [];
      this.forEach(function (value, name) {
        items.push([name, value]);
      });
      return iteratorFor(items);
    };

    if (support.iterable) {
      Headers.prototype[Symbol.iterator] = Headers.prototype.entries;
    }

    function consumed(body) {
      if (body.bodyUsed) {
        return Promise.reject(new TypeError('Already read'));
      }

      body.bodyUsed = true;
    }

    function fileReaderReady(reader) {
      return new Promise(function (resolve, reject) {
        reader.onload = function () {
          resolve(reader.result);
        };

        reader.onerror = function () {
          reject(reader.error);
        };
      });
    }

    function readBlobAsArrayBuffer(blob) {
      var reader = new FileReader();
      var promise = fileReaderReady(reader);
      reader.readAsArrayBuffer(blob);
      return promise;
    }

    function readBlobAsText(blob) {
      var reader = new FileReader();
      var promise = fileReaderReady(reader);
      reader.readAsText(blob);
      return promise;
    }

    function readArrayBufferAsText(buf) {
      var view = new Uint8Array(buf);
      var chars = new Array(view.length);

      for (var i = 0; i < view.length; i++) {
        chars[i] = String.fromCharCode(view[i]);
      }

      return chars.join('');
    }

    function bufferClone(buf) {
      if (buf.slice) {
        return buf.slice(0);
      } else {
        var view = new Uint8Array(buf.byteLength);
        view.set(new Uint8Array(buf));
        return view.buffer;
      }
    }

    function Body() {
      this.bodyUsed = false;

      this._initBody = function (body) {
        this._bodyInit = body;

        if (!body) {
          this._bodyText = '';
        } else if (typeof body === 'string') {
          this._bodyText = body;
        } else if (support.blob && Blob.prototype.isPrototypeOf(body)) {
          this._bodyBlob = body;
        } else if (support.formData && FormData.prototype.isPrototypeOf(body)) {
          this._bodyFormData = body;
        } else if (support.searchParams && URLSearchParams.prototype.isPrototypeOf(body)) {
          this._bodyText = body.toString();
        } else if (support.arrayBuffer && support.blob && isDataView(body)) {
          this._bodyArrayBuffer = bufferClone(body.buffer); // IE 10-11 can't handle a DataView body.

          this._bodyInit = new Blob([this._bodyArrayBuffer]);
        } else if (support.arrayBuffer && (ArrayBuffer.prototype.isPrototypeOf(body) || isArrayBufferView(body))) {
          this._bodyArrayBuffer = bufferClone(body);
        } else {
          this._bodyText = body = Object.prototype.toString.call(body);
        }

        if (!this.headers.get('content-type')) {
          if (typeof body === 'string') {
            this.headers.set('content-type', 'text/plain;charset=UTF-8');
          } else if (this._bodyBlob && this._bodyBlob.type) {
            this.headers.set('content-type', this._bodyBlob.type);
          } else if (support.searchParams && URLSearchParams.prototype.isPrototypeOf(body)) {
            this.headers.set('content-type', 'application/x-www-form-urlencoded;charset=UTF-8');
          }
        }
      };

      if (support.blob) {
        this.blob = function () {
          var rejected = consumed(this);

          if (rejected) {
            return rejected;
          }

          if (this._bodyBlob) {
            return Promise.resolve(this._bodyBlob);
          } else if (this._bodyArrayBuffer) {
            return Promise.resolve(new Blob([this._bodyArrayBuffer]));
          } else if (this._bodyFormData) {
            throw new Error('could not read FormData body as blob');
          } else {
            return Promise.resolve(new Blob([this._bodyText]));
          }
        };

        this.arrayBuffer = function () {
          if (this._bodyArrayBuffer) {
            return consumed(this) || Promise.resolve(this._bodyArrayBuffer);
          } else {
            return this.blob().then(readBlobAsArrayBuffer);
          }
        };
      }

      this.text = function () {
        var rejected = consumed(this);

        if (rejected) {
          return rejected;
        }

        if (this._bodyBlob) {
          return readBlobAsText(this._bodyBlob);
        } else if (this._bodyArrayBuffer) {
          return Promise.resolve(readArrayBufferAsText(this._bodyArrayBuffer));
        } else if (this._bodyFormData) {
          throw new Error('could not read FormData body as text');
        } else {
          return Promise.resolve(this._bodyText);
        }
      };

      if (support.formData) {
        this.formData = function () {
          return this.text().then(decode);
        };
      }

      this.json = function () {
        return this.text().then(JSON.parse);
      };

      return this;
    } // HTTP methods whose capitalization should be normalized


    var methods = ['DELETE', 'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT'];

    function normalizeMethod(method) {
      var upcased = method.toUpperCase();
      return methods.indexOf(upcased) > -1 ? upcased : method;
    }

    function Request(input, options) {
      options = options || {};
      var body = options.body;

      if (input instanceof Request) {
        if (input.bodyUsed) {
          throw new TypeError('Already read');
        }

        this.url = input.url;
        this.credentials = input.credentials;

        if (!options.headers) {
          this.headers = new Headers(input.headers);
        }

        this.method = input.method;
        this.mode = input.mode;
        this.signal = input.signal;

        if (!body && input._bodyInit != null) {
          body = input._bodyInit;
          input.bodyUsed = true;
        }
      } else {
        this.url = String(input);
      }

      this.credentials = options.credentials || this.credentials || 'same-origin';

      if (options.headers || !this.headers) {
        this.headers = new Headers(options.headers);
      }

      this.method = normalizeMethod(options.method || this.method || 'GET');
      this.mode = options.mode || this.mode || null;
      this.signal = options.signal || this.signal;
      this.referrer = null;

      if ((this.method === 'GET' || this.method === 'HEAD') && body) {
        throw new TypeError('Body not allowed for GET or HEAD requests');
      }

      this._initBody(body);
    }

    Request.prototype.clone = function () {
      return new Request(this, {
        body: this._bodyInit
      });
    };

    function decode(body) {
      var form = new FormData();
      body.trim().split('&').forEach(function (bytes) {
        if (bytes) {
          var split = bytes.split('=');
          var name = split.shift().replace(/\+/g, ' ');
          var value = split.join('=').replace(/\+/g, ' ');
          form.append(decodeURIComponent(name), decodeURIComponent(value));
        }
      });
      return form;
    }

    function parseHeaders(rawHeaders) {
      var headers = new Headers(); // Replace instances of \r\n and \n followed by at least one space or horizontal tab with a space
      // https://tools.ietf.org/html/rfc7230#section-3.2

      var preProcessedHeaders = rawHeaders.replace(/\r?\n[\t ]+/g, ' ');
      preProcessedHeaders.split(/\r?\n/).forEach(function (line) {
        var parts = line.split(':');
        var key = parts.shift().trim();

        if (key) {
          var value = parts.join(':').trim();
          headers.append(key, value);
        }
      });
      return headers;
    }

    Body.call(Request.prototype);

    function Response(bodyInit, options) {
      if (!options) {
        options = {};
      }

      this.type = 'default';
      this.status = options.status === undefined ? 200 : options.status;
      this.ok = this.status >= 200 && this.status < 300;
      this.statusText = 'statusText' in options ? options.statusText : 'OK';
      this.headers = new Headers(options.headers);
      this.url = options.url || '';

      this._initBody(bodyInit);
    }

    Body.call(Response.prototype);

    Response.prototype.clone = function () {
      return new Response(this._bodyInit, {
        status: this.status,
        statusText: this.statusText,
        headers: new Headers(this.headers),
        url: this.url
      });
    };

    Response.error = function () {
      var response = new Response(null, {
        status: 0,
        statusText: ''
      });
      response.type = 'error';
      return response;
    };

    var redirectStatuses = [301, 302, 303, 307, 308];

    Response.redirect = function (url, status) {
      if (redirectStatuses.indexOf(status) === -1) {
        throw new RangeError('Invalid status code');
      }

      return new Response(null, {
        status: status,
        headers: {
          location: url
        }
      });
    };

    exports.DOMException = self.DOMException;

    try {
      new exports.DOMException();
    } catch (err) {
      exports.DOMException = function (message, name) {
        this.message = message;
        this.name = name;
        var error = Error(message);
        this.stack = error.stack;
      };

      exports.DOMException.prototype = Object.create(Error.prototype);
      exports.DOMException.prototype.constructor = exports.DOMException;
    }

    function fetch(input, init) {
      return new Promise(function (resolve, reject) {
        var request = new Request(input, init);

        if (request.signal && request.signal.aborted) {
          return reject(new exports.DOMException('Aborted', 'AbortError'));
        }

        var xhr = new XMLHttpRequest();

        function abortXhr() {
          xhr.abort();
        }

        xhr.onload = function () {
          var options = {
            status: xhr.status,
            statusText: xhr.statusText,
            headers: parseHeaders(xhr.getAllResponseHeaders() || '')
          };
          options.url = 'responseURL' in xhr ? xhr.responseURL : options.headers.get('X-Request-URL');
          var body = 'response' in xhr ? xhr.response : xhr.responseText;
          resolve(new Response(body, options));
        };

        xhr.onerror = function () {
          reject(new TypeError('Network request failed'));
        };

        xhr.ontimeout = function () {
          reject(new TypeError('Network request failed'));
        };

        xhr.onabort = function () {
          reject(new exports.DOMException('Aborted', 'AbortError'));
        };

        xhr.open(request.method, request.url, true);

        if (request.credentials === 'include') {
          xhr.withCredentials = true;
        } else if (request.credentials === 'omit') {
          xhr.withCredentials = false;
        }

        if ('responseType' in xhr && support.blob) {
          xhr.responseType = 'blob';
        }

        request.headers.forEach(function (value, name) {
          xhr.setRequestHeader(name, value);
        });

        if (request.signal) {
          request.signal.addEventListener('abort', abortXhr);

          xhr.onreadystatechange = function () {
            // DONE (success or failure)
            if (xhr.readyState === 4) {
              request.signal.removeEventListener('abort', abortXhr);
            }
          };
        }

        xhr.send(typeof request._bodyInit === 'undefined' ? null : request._bodyInit);
      });
    }

    fetch.polyfill = true;

    if (!self.fetch) {
      self.fetch = fetch;
      self.Headers = Headers;
      self.Request = Request;
      self.Response = Response;
    }

    exports.Headers = Headers;
    exports.Request = Request;
    exports.Response = Response;
    exports.fetch = fetch;
    Object.defineProperty(exports, '__esModule', {
      value: true
    });
    return exports;
  }({});
})(__self__);

__self__.fetch.ponyfill = true; // Remove "polyfill" property added by whatwg-fetch

delete __self__.fetch.polyfill; // Choose between native implementation (global) or custom implementation (__self__)
// var ctx = global.fetch ? global : __self__;

var ctx = __self__; // this line disable service worker support temporarily

exports = ctx.fetch; // To enable: import fetch from 'cross-fetch'

exports.default = ctx.fetch; // For TypeScript consumers without esModuleInterop.

exports.fetch = ctx.fetch; // To enable: import {fetch} from 'cross-fetch'

exports.Headers = ctx.Headers;
exports.Request = ctx.Request;
exports.Response = ctx.Response;
module.exports = exports;

},{}],46:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

var R = typeof Reflect === 'object' ? Reflect : null
var ReflectApply = R && typeof R.apply === 'function'
  ? R.apply
  : function ReflectApply(target, receiver, args) {
    return Function.prototype.apply.call(target, receiver, args);
  }

var ReflectOwnKeys
if (R && typeof R.ownKeys === 'function') {
  ReflectOwnKeys = R.ownKeys
} else if (Object.getOwnPropertySymbols) {
  ReflectOwnKeys = function ReflectOwnKeys(target) {
    return Object.getOwnPropertyNames(target)
      .concat(Object.getOwnPropertySymbols(target));
  };
} else {
  ReflectOwnKeys = function ReflectOwnKeys(target) {
    return Object.getOwnPropertyNames(target);
  };
}

function ProcessEmitWarning(warning) {
  if (console && console.warn) console.warn(warning);
}

var NumberIsNaN = Number.isNaN || function NumberIsNaN(value) {
  return value !== value;
}

function EventEmitter() {
  EventEmitter.init.call(this);
}
module.exports = EventEmitter;
module.exports.once = once;

// Backwards-compat with node 0.10.x
EventEmitter.EventEmitter = EventEmitter;

EventEmitter.prototype._events = undefined;
EventEmitter.prototype._eventsCount = 0;
EventEmitter.prototype._maxListeners = undefined;

// By default EventEmitters will print a warning if more than 10 listeners are
// added to it. This is a useful default which helps finding memory leaks.
var defaultMaxListeners = 10;

function checkListener(listener) {
  if (typeof listener !== 'function') {
    throw new TypeError('The "listener" argument must be of type Function. Received type ' + typeof listener);
  }
}

Object.defineProperty(EventEmitter, 'defaultMaxListeners', {
  enumerable: true,
  get: function() {
    return defaultMaxListeners;
  },
  set: function(arg) {
    if (typeof arg !== 'number' || arg < 0 || NumberIsNaN(arg)) {
      throw new RangeError('The value of "defaultMaxListeners" is out of range. It must be a non-negative number. Received ' + arg + '.');
    }
    defaultMaxListeners = arg;
  }
});

EventEmitter.init = function() {

  if (this._events === undefined ||
      this._events === Object.getPrototypeOf(this)._events) {
    this._events = Object.create(null);
    this._eventsCount = 0;
  }

  this._maxListeners = this._maxListeners || undefined;
};

// Obviously not all Emitters should be limited to 10. This function allows
// that to be increased. Set to zero for unlimited.
EventEmitter.prototype.setMaxListeners = function setMaxListeners(n) {
  if (typeof n !== 'number' || n < 0 || NumberIsNaN(n)) {
    throw new RangeError('The value of "n" is out of range. It must be a non-negative number. Received ' + n + '.');
  }
  this._maxListeners = n;
  return this;
};

function _getMaxListeners(that) {
  if (that._maxListeners === undefined)
    return EventEmitter.defaultMaxListeners;
  return that._maxListeners;
}

EventEmitter.prototype.getMaxListeners = function getMaxListeners() {
  return _getMaxListeners(this);
};

EventEmitter.prototype.emit = function emit(type) {
  var args = [];
  for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
  var doError = (type === 'error');

  var events = this._events;
  if (events !== undefined)
    doError = (doError && events.error === undefined);
  else if (!doError)
    return false;

  // If there is no 'error' event listener then throw.
  if (doError) {
    var er;
    if (args.length > 0)
      er = args[0];
    if (er instanceof Error) {
      // Note: The comments on the `throw` lines are intentional, they show
      // up in Node's output if this results in an unhandled exception.
      throw er; // Unhandled 'error' event
    }
    // At least give some kind of context to the user
    var err = new Error('Unhandled error.' + (er ? ' (' + er.message + ')' : ''));
    err.context = er;
    throw err; // Unhandled 'error' event
  }

  var handler = events[type];

  if (handler === undefined)
    return false;

  if (typeof handler === 'function') {
    ReflectApply(handler, this, args);
  } else {
    var len = handler.length;
    var listeners = arrayClone(handler, len);
    for (var i = 0; i < len; ++i)
      ReflectApply(listeners[i], this, args);
  }

  return true;
};

function _addListener(target, type, listener, prepend) {
  var m;
  var events;
  var existing;

  checkListener(listener);

  events = target._events;
  if (events === undefined) {
    events = target._events = Object.create(null);
    target._eventsCount = 0;
  } else {
    // To avoid recursion in the case that type === "newListener"! Before
    // adding it to the listeners, first emit "newListener".
    if (events.newListener !== undefined) {
      target.emit('newListener', type,
                  listener.listener ? listener.listener : listener);

      // Re-assign `events` because a newListener handler could have caused the
      // this._events to be assigned to a new object
      events = target._events;
    }
    existing = events[type];
  }

  if (existing === undefined) {
    // Optimize the case of one listener. Don't need the extra array object.
    existing = events[type] = listener;
    ++target._eventsCount;
  } else {
    if (typeof existing === 'function') {
      // Adding the second element, need to change to array.
      existing = events[type] =
        prepend ? [listener, existing] : [existing, listener];
      // If we've already got an array, just append.
    } else if (prepend) {
      existing.unshift(listener);
    } else {
      existing.push(listener);
    }

    // Check for listener leak
    m = _getMaxListeners(target);
    if (m > 0 && existing.length > m && !existing.warned) {
      existing.warned = true;
      // No error code for this since it is a Warning
      // eslint-disable-next-line no-restricted-syntax
      var w = new Error('Possible EventEmitter memory leak detected. ' +
                          existing.length + ' ' + String(type) + ' listeners ' +
                          'added. Use emitter.setMaxListeners() to ' +
                          'increase limit');
      w.name = 'MaxListenersExceededWarning';
      w.emitter = target;
      w.type = type;
      w.count = existing.length;
      ProcessEmitWarning(w);
    }
  }

  return target;
}

EventEmitter.prototype.addListener = function addListener(type, listener) {
  return _addListener(this, type, listener, false);
};

EventEmitter.prototype.on = EventEmitter.prototype.addListener;

EventEmitter.prototype.prependListener =
    function prependListener(type, listener) {
      return _addListener(this, type, listener, true);
    };

function onceWrapper() {
  if (!this.fired) {
    this.target.removeListener(this.type, this.wrapFn);
    this.fired = true;
    if (arguments.length === 0)
      return this.listener.call(this.target);
    return this.listener.apply(this.target, arguments);
  }
}

function _onceWrap(target, type, listener) {
  var state = { fired: false, wrapFn: undefined, target: target, type: type, listener: listener };
  var wrapped = onceWrapper.bind(state);
  wrapped.listener = listener;
  state.wrapFn = wrapped;
  return wrapped;
}

EventEmitter.prototype.once = function once(type, listener) {
  checkListener(listener);
  this.on(type, _onceWrap(this, type, listener));
  return this;
};

EventEmitter.prototype.prependOnceListener =
    function prependOnceListener(type, listener) {
      checkListener(listener);
      this.prependListener(type, _onceWrap(this, type, listener));
      return this;
    };

// Emits a 'removeListener' event if and only if the listener was removed.
EventEmitter.prototype.removeListener =
    function removeListener(type, listener) {
      var list, events, position, i, originalListener;

      checkListener(listener);

      events = this._events;
      if (events === undefined)
        return this;

      list = events[type];
      if (list === undefined)
        return this;

      if (list === listener || list.listener === listener) {
        if (--this._eventsCount === 0)
          this._events = Object.create(null);
        else {
          delete events[type];
          if (events.removeListener)
            this.emit('removeListener', type, list.listener || listener);
        }
      } else if (typeof list !== 'function') {
        position = -1;

        for (i = list.length - 1; i >= 0; i--) {
          if (list[i] === listener || list[i].listener === listener) {
            originalListener = list[i].listener;
            position = i;
            break;
          }
        }

        if (position < 0)
          return this;

        if (position === 0)
          list.shift();
        else {
          spliceOne(list, position);
        }

        if (list.length === 1)
          events[type] = list[0];

        if (events.removeListener !== undefined)
          this.emit('removeListener', type, originalListener || listener);
      }

      return this;
    };

EventEmitter.prototype.off = EventEmitter.prototype.removeListener;

EventEmitter.prototype.removeAllListeners =
    function removeAllListeners(type) {
      var listeners, events, i;

      events = this._events;
      if (events === undefined)
        return this;

      // not listening for removeListener, no need to emit
      if (events.removeListener === undefined) {
        if (arguments.length === 0) {
          this._events = Object.create(null);
          this._eventsCount = 0;
        } else if (events[type] !== undefined) {
          if (--this._eventsCount === 0)
            this._events = Object.create(null);
          else
            delete events[type];
        }
        return this;
      }

      // emit removeListener for all listeners on all events
      if (arguments.length === 0) {
        var keys = Object.keys(events);
        var key;
        for (i = 0; i < keys.length; ++i) {
          key = keys[i];
          if (key === 'removeListener') continue;
          this.removeAllListeners(key);
        }
        this.removeAllListeners('removeListener');
        this._events = Object.create(null);
        this._eventsCount = 0;
        return this;
      }

      listeners = events[type];

      if (typeof listeners === 'function') {
        this.removeListener(type, listeners);
      } else if (listeners !== undefined) {
        // LIFO order
        for (i = listeners.length - 1; i >= 0; i--) {
          this.removeListener(type, listeners[i]);
        }
      }

      return this;
    };

function _listeners(target, type, unwrap) {
  var events = target._events;

  if (events === undefined)
    return [];

  var evlistener = events[type];
  if (evlistener === undefined)
    return [];

  if (typeof evlistener === 'function')
    return unwrap ? [evlistener.listener || evlistener] : [evlistener];

  return unwrap ?
    unwrapListeners(evlistener) : arrayClone(evlistener, evlistener.length);
}

EventEmitter.prototype.listeners = function listeners(type) {
  return _listeners(this, type, true);
};

EventEmitter.prototype.rawListeners = function rawListeners(type) {
  return _listeners(this, type, false);
};

EventEmitter.listenerCount = function(emitter, type) {
  if (typeof emitter.listenerCount === 'function') {
    return emitter.listenerCount(type);
  } else {
    return listenerCount.call(emitter, type);
  }
};

EventEmitter.prototype.listenerCount = listenerCount;
function listenerCount(type) {
  var events = this._events;

  if (events !== undefined) {
    var evlistener = events[type];

    if (typeof evlistener === 'function') {
      return 1;
    } else if (evlistener !== undefined) {
      return evlistener.length;
    }
  }

  return 0;
}

EventEmitter.prototype.eventNames = function eventNames() {
  return this._eventsCount > 0 ? ReflectOwnKeys(this._events) : [];
};

function arrayClone(arr, n) {
  var copy = new Array(n);
  for (var i = 0; i < n; ++i)
    copy[i] = arr[i];
  return copy;
}

function spliceOne(list, index) {
  for (; index + 1 < list.length; index++)
    list[index] = list[index + 1];
  list.pop();
}

function unwrapListeners(arr) {
  var ret = new Array(arr.length);
  for (var i = 0; i < ret.length; ++i) {
    ret[i] = arr[i].listener || arr[i];
  }
  return ret;
}

function once(emitter, name) {
  return new Promise(function (resolve, reject) {
    function errorListener(err) {
      emitter.removeListener(name, resolver);
      reject(err);
    }

    function resolver() {
      if (typeof emitter.removeListener === 'function') {
        emitter.removeListener('error', errorListener);
      }
      resolve([].slice.call(arguments));
    };

    eventTargetAgnosticAddListener(emitter, name, resolver, { once: true });
    if (name !== 'error') {
      addErrorHandlerIfEventEmitter(emitter, errorListener, { once: true });
    }
  });
}

function addErrorHandlerIfEventEmitter(emitter, handler, flags) {
  if (typeof emitter.on === 'function') {
    eventTargetAgnosticAddListener(emitter, 'error', handler, flags);
  }
}

function eventTargetAgnosticAddListener(emitter, name, listener, flags) {
  if (typeof emitter.on === 'function') {
    if (flags.once) {
      emitter.once(name, listener);
    } else {
      emitter.on(name, listener);
    }
  } else if (typeof emitter.addEventListener === 'function') {
    // EventTarget does not have `error` event semantics like Node
    // EventEmitters, we do not listen for `error` events here.
    emitter.addEventListener(name, function wrapListener(arg) {
      // IE does not have builtin `{ once: true }` support so we
      // have to do it manually.
      if (flags.once) {
        emitter.removeEventListener(name, wrapListener);
      }
      listener(arg);
    });
  } else {
    throw new TypeError('The "emitter" argument must be of type EventEmitter. Received type ' + typeof emitter);
  }
}

},{}],47:[function(require,module,exports){
module.exports = (data, opts = {}) => {
  const {
    sorted, skipIndex, ignorenull, skipBracket, useDot, whitespace = '+'
  } = opts;

  const encode = value => String(value)
    .replace(/[^ !'()~*]/gu, encodeURIComponent)
    .replace(/ /g, whitespace)
    .replace(/[!'()~*]/g, ch =>
      `%${ch.charCodeAt().toString(16).slice(-2).toUpperCase()}`);

  const keys = (obj, keyarr = Object.keys(obj)) =>
    sorted ? keyarr.sort() : keyarr;

  const filterjoin = arr => arr.filter(e => e).join('&');

  const objnest = (name, obj) => filterjoin(keys(obj).map(key => useDot
    ? nest(`${name}.${key}`, obj[key])
    : nest(`${name}[${key}]`, obj[key])));

  const arrnest = (name, arr, brackets = skipBracket ? '' : '[]') => arr.length
    ? filterjoin(arr.map((elem, index) => skipIndex
      ? nest(name + brackets, elem)
      : nest(name + '[' + index + ']', elem)))
    : encode(name + brackets);

  const setnest = (name, set) => filterjoin(
    Array.from(set).map(elem => nest(name, elem)));

  const nest = (name, value, type = typeof value, f = null) => {
    if (value === f)
      f = ignorenull ? f : encode(name) + '=' + f;
    else if (/string|number|boolean/.test(type))
      f = encode(name) + '=' + encode(value);
    else if (Array.isArray(value))
      f = arrnest(name, value);
    else if (value instanceof Set)
      f = setnest(name, value);
    else if (type === 'object')
      f = objnest(name, value);

    return f;
  };

  return data && filterjoin(keys(data).map(key => nest(key, data[key])));
};

},{}],48:[function(require,module,exports){
/*! ieee754. BSD-3-Clause License. Feross Aboukhadijeh <https://feross.org/opensource> */
exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = (e * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = (m * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  var i = isLE ? 0 : (nBytes - 1)
  var d = isLE ? 1 : -1
  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = ((value * c) - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = (e << mLen) | m
  eLen += mLen
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128
}

},{}],49:[function(require,module,exports){
if (typeof Object.create === 'function') {
  // implementation from standard node.js 'util' module
  module.exports = function inherits(ctor, superCtor) {
    if (superCtor) {
      ctor.super_ = superCtor
      ctor.prototype = Object.create(superCtor.prototype, {
        constructor: {
          value: ctor,
          enumerable: false,
          writable: true,
          configurable: true
        }
      })
    }
  };
} else {
  // old school shim for old browsers
  module.exports = function inherits(ctor, superCtor) {
    if (superCtor) {
      ctor.super_ = superCtor
      var TempCtor = function () {}
      TempCtor.prototype = superCtor.prototype
      ctor.prototype = new TempCtor()
      ctor.prototype.constructor = ctor
    }
  }
}

},{}],50:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
Object.defineProperty(exports, "CompactEncrypt", {
  enumerable: true,
  get: function () {
    return _encrypt2.CompactEncrypt;
  }
});
Object.defineProperty(exports, "CompactSign", {
  enumerable: true,
  get: function () {
    return _sign.CompactSign;
  }
});
Object.defineProperty(exports, "EmbeddedJWK", {
  enumerable: true,
  get: function () {
    return _embedded.EmbeddedJWK;
  }
});
Object.defineProperty(exports, "EncryptJWT", {
  enumerable: true,
  get: function () {
    return _encrypt4.EncryptJWT;
  }
});
Object.defineProperty(exports, "FlattenedEncrypt", {
  enumerable: true,
  get: function () {
    return _encrypt3.FlattenedEncrypt;
  }
});
Object.defineProperty(exports, "FlattenedSign", {
  enumerable: true,
  get: function () {
    return _sign2.FlattenedSign;
  }
});
Object.defineProperty(exports, "GeneralEncrypt", {
  enumerable: true,
  get: function () {
    return _encrypt.GeneralEncrypt;
  }
});
Object.defineProperty(exports, "GeneralSign", {
  enumerable: true,
  get: function () {
    return _sign3.GeneralSign;
  }
});
Object.defineProperty(exports, "SignJWT", {
  enumerable: true,
  get: function () {
    return _sign4.SignJWT;
  }
});
Object.defineProperty(exports, "UnsecuredJWT", {
  enumerable: true,
  get: function () {
    return _unsecured.UnsecuredJWT;
  }
});
exports.base64url = void 0;
Object.defineProperty(exports, "calculateJwkThumbprint", {
  enumerable: true,
  get: function () {
    return _thumbprint.calculateJwkThumbprint;
  }
});
Object.defineProperty(exports, "compactDecrypt", {
  enumerable: true,
  get: function () {
    return _decrypt.compactDecrypt;
  }
});
Object.defineProperty(exports, "compactVerify", {
  enumerable: true,
  get: function () {
    return _verify.compactVerify;
  }
});
Object.defineProperty(exports, "createRemoteJWKSet", {
  enumerable: true,
  get: function () {
    return _remote.createRemoteJWKSet;
  }
});
Object.defineProperty(exports, "decodeProtectedHeader", {
  enumerable: true,
  get: function () {
    return _decode_protected_header.decodeProtectedHeader;
  }
});
exports.errors = void 0;
Object.defineProperty(exports, "exportJWK", {
  enumerable: true,
  get: function () {
    return _export.exportJWK;
  }
});
Object.defineProperty(exports, "exportPKCS8", {
  enumerable: true,
  get: function () {
    return _export.exportPKCS8;
  }
});
Object.defineProperty(exports, "exportSPKI", {
  enumerable: true,
  get: function () {
    return _export.exportSPKI;
  }
});
Object.defineProperty(exports, "flattenedDecrypt", {
  enumerable: true,
  get: function () {
    return _decrypt2.flattenedDecrypt;
  }
});
Object.defineProperty(exports, "flattenedVerify", {
  enumerable: true,
  get: function () {
    return _verify2.flattenedVerify;
  }
});
Object.defineProperty(exports, "generalDecrypt", {
  enumerable: true,
  get: function () {
    return _decrypt3.generalDecrypt;
  }
});
Object.defineProperty(exports, "generalVerify", {
  enumerable: true,
  get: function () {
    return _verify3.generalVerify;
  }
});
Object.defineProperty(exports, "generateKeyPair", {
  enumerable: true,
  get: function () {
    return _generate_key_pair.generateKeyPair;
  }
});
Object.defineProperty(exports, "generateSecret", {
  enumerable: true,
  get: function () {
    return _generate_secret.generateSecret;
  }
});
Object.defineProperty(exports, "importJWK", {
  enumerable: true,
  get: function () {
    return _import.importJWK;
  }
});
Object.defineProperty(exports, "importPKCS8", {
  enumerable: true,
  get: function () {
    return _import.importPKCS8;
  }
});
Object.defineProperty(exports, "importSPKI", {
  enumerable: true,
  get: function () {
    return _import.importSPKI;
  }
});
Object.defineProperty(exports, "importX509", {
  enumerable: true,
  get: function () {
    return _import.importX509;
  }
});
Object.defineProperty(exports, "jwtDecrypt", {
  enumerable: true,
  get: function () {
    return _decrypt4.jwtDecrypt;
  }
});
Object.defineProperty(exports, "jwtVerify", {
  enumerable: true,
  get: function () {
    return _verify4.jwtVerify;
  }
});

var _decrypt = require("./jwe/compact/decrypt.js");

var _decrypt2 = require("./jwe/flattened/decrypt.js");

var _decrypt3 = require("./jwe/general/decrypt.js");

var _encrypt = require("./jwe/general/encrypt.js");

var _verify = require("./jws/compact/verify.js");

var _verify2 = require("./jws/flattened/verify.js");

var _verify3 = require("./jws/general/verify.js");

var _verify4 = require("./jwt/verify.js");

var _decrypt4 = require("./jwt/decrypt.js");

var _encrypt2 = require("./jwe/compact/encrypt.js");

var _encrypt3 = require("./jwe/flattened/encrypt.js");

var _sign = require("./jws/compact/sign.js");

var _sign2 = require("./jws/flattened/sign.js");

var _sign3 = require("./jws/general/sign.js");

var _sign4 = require("./jwt/sign.js");

var _encrypt4 = require("./jwt/encrypt.js");

var _thumbprint = require("./jwk/thumbprint.js");

var _embedded = require("./jwk/embedded.js");

var _remote = require("./jwks/remote.js");

var _unsecured = require("./jwt/unsecured.js");

var _export = require("./key/export.js");

var _import = require("./key/import.js");

var _decode_protected_header = require("./util/decode_protected_header.js");

var errors_1 = _interopRequireWildcard(require("./util/errors.js"));

exports.errors = errors_1;

var _generate_key_pair = require("./key/generate_key_pair.js");

var _generate_secret = require("./key/generate_secret.js");

var base64url_1 = _interopRequireWildcard(require("./util/base64url.js"));

exports.base64url = base64url_1;

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

},{"./jwe/compact/decrypt.js":51,"./jwe/compact/encrypt.js":52,"./jwe/flattened/decrypt.js":53,"./jwe/flattened/encrypt.js":54,"./jwe/general/decrypt.js":55,"./jwe/general/encrypt.js":56,"./jwk/embedded.js":57,"./jwk/thumbprint.js":58,"./jwks/remote.js":59,"./jws/compact/sign.js":60,"./jws/compact/verify.js":61,"./jws/flattened/sign.js":62,"./jws/flattened/verify.js":63,"./jws/general/sign.js":64,"./jws/general/verify.js":65,"./jwt/decrypt.js":66,"./jwt/encrypt.js":67,"./jwt/sign.js":69,"./jwt/unsecured.js":70,"./jwt/verify.js":71,"./key/export.js":72,"./key/generate_key_pair.js":73,"./key/generate_secret.js":74,"./key/import.js":75,"./util/base64url.js":122,"./util/decode_protected_header.js":123,"./util/errors.js":124}],51:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.compactDecrypt = compactDecrypt;

var _decrypt = require("../flattened/decrypt.js");

var _errors = require("../../util/errors.js");

var _buffer_utils = require("../../lib/buffer_utils.js");

async function compactDecrypt(jwe, key, options) {
  if (jwe instanceof Uint8Array) {
    jwe = _buffer_utils.decoder.decode(jwe);
  }

  if (typeof jwe !== 'string') {
    throw new _errors.JWEInvalid('Compact JWE must be a string or Uint8Array');
  }

  const {
    0: protectedHeader,
    1: encryptedKey,
    2: iv,
    3: ciphertext,
    4: tag,
    length
  } = jwe.split('.');

  if (length !== 5) {
    throw new _errors.JWEInvalid('Invalid Compact JWE');
  }

  const decrypted = await (0, _decrypt.flattenedDecrypt)({
    ciphertext: ciphertext || undefined,
    iv: iv || undefined,
    protected: protectedHeader || undefined,
    tag: tag || undefined,
    encrypted_key: encryptedKey || undefined
  }, key, options);
  const result = {
    plaintext: decrypted.plaintext,
    protectedHeader: decrypted.protectedHeader
  };

  if (typeof key === 'function') {
    return { ...result,
      key: decrypted.key
    };
  }

  return result;
}

},{"../../lib/buffer_utils.js":77,"../../util/errors.js":124,"../flattened/decrypt.js":53}],52:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.CompactEncrypt = void 0;

var _encrypt = require("../flattened/encrypt.js");

class CompactEncrypt {
  constructor(plaintext) {
    this._flattened = new _encrypt.FlattenedEncrypt(plaintext);
  }

  setContentEncryptionKey(cek) {
    this._flattened.setContentEncryptionKey(cek);

    return this;
  }

  setInitializationVector(iv) {
    this._flattened.setInitializationVector(iv);

    return this;
  }

  setProtectedHeader(protectedHeader) {
    this._flattened.setProtectedHeader(protectedHeader);

    return this;
  }

  setKeyManagementParameters(parameters) {
    this._flattened.setKeyManagementParameters(parameters);

    return this;
  }

  async encrypt(key, options) {
    const jwe = await this._flattened.encrypt(key, options);
    return [jwe.protected, jwe.encrypted_key, jwe.iv, jwe.ciphertext, jwe.tag].join('.');
  }

}

exports.CompactEncrypt = CompactEncrypt;

},{"../flattened/encrypt.js":54}],53:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.flattenedDecrypt = flattenedDecrypt;

var _base64url = require("../../runtime/base64url.js");

var _decrypt = _interopRequireDefault(require("../../runtime/decrypt.js"));

var _zlib = require("../../runtime/zlib.js");

var _errors = require("../../util/errors.js");

var _is_disjoint = _interopRequireDefault(require("../../lib/is_disjoint.js"));

var _is_object = _interopRequireDefault(require("../../lib/is_object.js"));

var _decrypt_key_management = _interopRequireDefault(require("../../lib/decrypt_key_management.js"));

var _buffer_utils = require("../../lib/buffer_utils.js");

var _cek = _interopRequireDefault(require("../../lib/cek.js"));

var _validate_crit = _interopRequireDefault(require("../../lib/validate_crit.js"));

var _validate_algorithms = _interopRequireDefault(require("../../lib/validate_algorithms.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

async function flattenedDecrypt(jwe, key, options) {
  var _a;

  if (!(0, _is_object.default)(jwe)) {
    throw new _errors.JWEInvalid('Flattened JWE must be an object');
  }

  if (jwe.protected === undefined && jwe.header === undefined && jwe.unprotected === undefined) {
    throw new _errors.JWEInvalid('JOSE Header missing');
  }

  if (typeof jwe.iv !== 'string') {
    throw new _errors.JWEInvalid('JWE Initialization Vector missing or incorrect type');
  }

  if (typeof jwe.ciphertext !== 'string') {
    throw new _errors.JWEInvalid('JWE Ciphertext missing or incorrect type');
  }

  if (typeof jwe.tag !== 'string') {
    throw new _errors.JWEInvalid('JWE Authentication Tag missing or incorrect type');
  }

  if (jwe.protected !== undefined && typeof jwe.protected !== 'string') {
    throw new _errors.JWEInvalid('JWE Protected Header incorrect type');
  }

  if (jwe.encrypted_key !== undefined && typeof jwe.encrypted_key !== 'string') {
    throw new _errors.JWEInvalid('JWE Encrypted Key incorrect type');
  }

  if (jwe.aad !== undefined && typeof jwe.aad !== 'string') {
    throw new _errors.JWEInvalid('JWE AAD incorrect type');
  }

  if (jwe.header !== undefined && !(0, _is_object.default)(jwe.header)) {
    throw new _errors.JWEInvalid('JWE Shared Unprotected Header incorrect type');
  }

  if (jwe.unprotected !== undefined && !(0, _is_object.default)(jwe.unprotected)) {
    throw new _errors.JWEInvalid('JWE Per-Recipient Unprotected Header incorrect type');
  }

  let parsedProt;

  if (jwe.protected) {
    const protectedHeader = (0, _base64url.decode)(jwe.protected);

    try {
      parsedProt = JSON.parse(_buffer_utils.decoder.decode(protectedHeader));
    } catch (_b) {
      throw new _errors.JWEInvalid('JWE Protected Header is invalid');
    }
  }

  if (!(0, _is_disjoint.default)(parsedProt, jwe.header, jwe.unprotected)) {
    throw new _errors.JWEInvalid('JWE Protected, JWE Unprotected Header, and JWE Per-Recipient Unprotected Header Parameter names must be disjoint');
  }

  const joseHeader = { ...parsedProt,
    ...jwe.header,
    ...jwe.unprotected
  };
  (0, _validate_crit.default)(_errors.JWEInvalid, new Map(), options === null || options === void 0 ? void 0 : options.crit, parsedProt, joseHeader);

  if (joseHeader.zip !== undefined) {
    if (!parsedProt || !parsedProt.zip) {
      throw new _errors.JWEInvalid('JWE "zip" (Compression Algorithm) Header MUST be integrity protected');
    }

    if (joseHeader.zip !== 'DEF') {
      throw new _errors.JOSENotSupported('Unsupported JWE "zip" (Compression Algorithm) Header Parameter value');
    }
  }

  const {
    alg,
    enc
  } = joseHeader;

  if (typeof alg !== 'string' || !alg) {
    throw new _errors.JWEInvalid('missing JWE Algorithm (alg) in JWE Header');
  }

  if (typeof enc !== 'string' || !enc) {
    throw new _errors.JWEInvalid('missing JWE Encryption Algorithm (enc) in JWE Header');
  }

  const keyManagementAlgorithms = options && (0, _validate_algorithms.default)('keyManagementAlgorithms', options.keyManagementAlgorithms);
  const contentEncryptionAlgorithms = options && (0, _validate_algorithms.default)('contentEncryptionAlgorithms', options.contentEncryptionAlgorithms);

  if (keyManagementAlgorithms && !keyManagementAlgorithms.has(alg)) {
    throw new _errors.JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter not allowed');
  }

  if (contentEncryptionAlgorithms && !contentEncryptionAlgorithms.has(enc)) {
    throw new _errors.JOSEAlgNotAllowed('"enc" (Encryption Algorithm) Header Parameter not allowed');
  }

  let encryptedKey;

  if (jwe.encrypted_key !== undefined) {
    encryptedKey = (0, _base64url.decode)(jwe.encrypted_key);
  }

  let resolvedKey = false;

  if (typeof key === 'function') {
    key = await key(parsedProt, jwe);
    resolvedKey = true;
  }

  let cek;

  try {
    cek = await (0, _decrypt_key_management.default)(alg, key, encryptedKey, joseHeader);
  } catch (err) {
    if (err instanceof TypeError) {
      throw err;
    }

    cek = (0, _cek.default)(enc);
  }

  const iv = (0, _base64url.decode)(jwe.iv);
  const tag = (0, _base64url.decode)(jwe.tag);

  const protectedHeader = _buffer_utils.encoder.encode((_a = jwe.protected) !== null && _a !== void 0 ? _a : '');

  let additionalData;

  if (jwe.aad !== undefined) {
    additionalData = (0, _buffer_utils.concat)(protectedHeader, _buffer_utils.encoder.encode('.'), _buffer_utils.encoder.encode(jwe.aad));
  } else {
    additionalData = protectedHeader;
  }

  let plaintext = await (0, _decrypt.default)(enc, cek, (0, _base64url.decode)(jwe.ciphertext), iv, tag, additionalData);

  if (joseHeader.zip === 'DEF') {
    plaintext = await ((options === null || options === void 0 ? void 0 : options.inflateRaw) || _zlib.inflate)(plaintext);
  }

  const result = {
    plaintext
  };

  if (jwe.protected !== undefined) {
    result.protectedHeader = parsedProt;
  }

  if (jwe.aad !== undefined) {
    result.additionalAuthenticatedData = (0, _base64url.decode)(jwe.aad);
  }

  if (jwe.unprotected !== undefined) {
    result.sharedUnprotectedHeader = jwe.unprotected;
  }

  if (jwe.header !== undefined) {
    result.unprotectedHeader = jwe.header;
  }

  if (resolvedKey) {
    return { ...result,
      key
    };
  }

  return result;
}

},{"../../lib/buffer_utils.js":77,"../../lib/cek.js":78,"../../lib/decrypt_key_management.js":83,"../../lib/is_disjoint.js":88,"../../lib/is_object.js":89,"../../lib/validate_algorithms.js":93,"../../lib/validate_crit.js":94,"../../runtime/base64url.js":97,"../../runtime/decrypt.js":101,"../../runtime/zlib.js":121,"../../util/errors.js":124}],54:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.unprotected = exports.FlattenedEncrypt = void 0;

var _base64url = require("../../runtime/base64url.js");

var _encrypt = _interopRequireDefault(require("../../runtime/encrypt.js"));

var _zlib = require("../../runtime/zlib.js");

var _iv = _interopRequireDefault(require("../../lib/iv.js"));

var _encrypt_key_management = _interopRequireDefault(require("../../lib/encrypt_key_management.js"));

var _errors = require("../../util/errors.js");

var _is_disjoint = _interopRequireDefault(require("../../lib/is_disjoint.js"));

var _buffer_utils = require("../../lib/buffer_utils.js");

var _validate_crit = _interopRequireDefault(require("../../lib/validate_crit.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const unprotected = Symbol();
exports.unprotected = unprotected;

class FlattenedEncrypt {
  constructor(plaintext) {
    if (!(plaintext instanceof Uint8Array)) {
      throw new TypeError('plaintext must be an instance of Uint8Array');
    }

    this._plaintext = plaintext;
  }

  setKeyManagementParameters(parameters) {
    if (this._keyManagementParameters) {
      throw new TypeError('setKeyManagementParameters can only be called once');
    }

    this._keyManagementParameters = parameters;
    return this;
  }

  setProtectedHeader(protectedHeader) {
    if (this._protectedHeader) {
      throw new TypeError('setProtectedHeader can only be called once');
    }

    this._protectedHeader = protectedHeader;
    return this;
  }

  setSharedUnprotectedHeader(sharedUnprotectedHeader) {
    if (this._sharedUnprotectedHeader) {
      throw new TypeError('setSharedUnprotectedHeader can only be called once');
    }

    this._sharedUnprotectedHeader = sharedUnprotectedHeader;
    return this;
  }

  setUnprotectedHeader(unprotectedHeader) {
    if (this._unprotectedHeader) {
      throw new TypeError('setUnprotectedHeader can only be called once');
    }

    this._unprotectedHeader = unprotectedHeader;
    return this;
  }

  setAdditionalAuthenticatedData(aad) {
    this._aad = aad;
    return this;
  }

  setContentEncryptionKey(cek) {
    if (this._cek) {
      throw new TypeError('setContentEncryptionKey can only be called once');
    }

    this._cek = cek;
    return this;
  }

  setInitializationVector(iv) {
    if (this._iv) {
      throw new TypeError('setInitializationVector can only be called once');
    }

    this._iv = iv;
    return this;
  }

  async encrypt(key, options) {
    if (!this._protectedHeader && !this._unprotectedHeader && !this._sharedUnprotectedHeader) {
      throw new _errors.JWEInvalid('either setProtectedHeader, setUnprotectedHeader, or sharedUnprotectedHeader must be called before #encrypt()');
    }

    if (!(0, _is_disjoint.default)(this._protectedHeader, this._unprotectedHeader, this._sharedUnprotectedHeader)) {
      throw new _errors.JWEInvalid('JWE Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint');
    }

    const joseHeader = { ...this._protectedHeader,
      ...this._unprotectedHeader,
      ...this._sharedUnprotectedHeader
    };
    (0, _validate_crit.default)(_errors.JWEInvalid, new Map(), options === null || options === void 0 ? void 0 : options.crit, this._protectedHeader, joseHeader);

    if (joseHeader.zip !== undefined) {
      if (!this._protectedHeader || !this._protectedHeader.zip) {
        throw new _errors.JWEInvalid('JWE "zip" (Compression Algorithm) Header MUST be integrity protected');
      }

      if (joseHeader.zip !== 'DEF') {
        throw new _errors.JOSENotSupported('Unsupported JWE "zip" (Compression Algorithm) Header Parameter value');
      }
    }

    const {
      alg,
      enc
    } = joseHeader;

    if (typeof alg !== 'string' || !alg) {
      throw new _errors.JWEInvalid('JWE "alg" (Algorithm) Header Parameter missing or invalid');
    }

    if (typeof enc !== 'string' || !enc) {
      throw new _errors.JWEInvalid('JWE "enc" (Encryption Algorithm) Header Parameter missing or invalid');
    }

    let encryptedKey;

    if (alg === 'dir') {
      if (this._cek) {
        throw new TypeError('setContentEncryptionKey cannot be called when using Direct Encryption');
      }
    } else if (alg === 'ECDH-ES') {
      if (this._cek) {
        throw new TypeError('setContentEncryptionKey cannot be called when using Direct Key Agreement');
      }
    }

    let cek;
    {
      let parameters;
      ({
        cek,
        encryptedKey,
        parameters
      } = await (0, _encrypt_key_management.default)(alg, enc, key, this._cek, this._keyManagementParameters));

      if (parameters) {
        if (options && unprotected in options) {
          if (!this._unprotectedHeader) {
            this.setUnprotectedHeader(parameters);
          } else {
            this._unprotectedHeader = { ...this._unprotectedHeader,
              ...parameters
            };
          }
        } else {
          if (!this._protectedHeader) {
            this.setProtectedHeader(parameters);
          } else {
            this._protectedHeader = { ...this._protectedHeader,
              ...parameters
            };
          }
        }
      }
    }
    this._iv || (this._iv = (0, _iv.default)(enc));
    let additionalData;
    let protectedHeader;
    let aadMember;

    if (this._protectedHeader) {
      protectedHeader = _buffer_utils.encoder.encode((0, _base64url.encode)(JSON.stringify(this._protectedHeader)));
    } else {
      protectedHeader = _buffer_utils.encoder.encode('');
    }

    if (this._aad) {
      aadMember = (0, _base64url.encode)(this._aad);
      additionalData = (0, _buffer_utils.concat)(protectedHeader, _buffer_utils.encoder.encode('.'), _buffer_utils.encoder.encode(aadMember));
    } else {
      additionalData = protectedHeader;
    }

    let ciphertext;
    let tag;

    if (joseHeader.zip === 'DEF') {
      const deflated = await ((options === null || options === void 0 ? void 0 : options.deflateRaw) || _zlib.deflate)(this._plaintext);
      ({
        ciphertext,
        tag
      } = await (0, _encrypt.default)(enc, deflated, cek, this._iv, additionalData));
    } else {
      ;
      ({
        ciphertext,
        tag
      } = await (0, _encrypt.default)(enc, this._plaintext, cek, this._iv, additionalData));
    }

    const jwe = {
      ciphertext: (0, _base64url.encode)(ciphertext),
      iv: (0, _base64url.encode)(this._iv),
      tag: (0, _base64url.encode)(tag)
    };

    if (encryptedKey) {
      jwe.encrypted_key = (0, _base64url.encode)(encryptedKey);
    }

    if (aadMember) {
      jwe.aad = aadMember;
    }

    if (this._protectedHeader) {
      jwe.protected = _buffer_utils.decoder.decode(protectedHeader);
    }

    if (this._sharedUnprotectedHeader) {
      jwe.unprotected = this._sharedUnprotectedHeader;
    }

    if (this._unprotectedHeader) {
      jwe.header = this._unprotectedHeader;
    }

    return jwe;
  }

}

exports.FlattenedEncrypt = FlattenedEncrypt;

},{"../../lib/buffer_utils.js":77,"../../lib/encrypt_key_management.js":84,"../../lib/is_disjoint.js":88,"../../lib/iv.js":90,"../../lib/validate_crit.js":94,"../../runtime/base64url.js":97,"../../runtime/encrypt.js":104,"../../runtime/zlib.js":121,"../../util/errors.js":124}],55:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.generalDecrypt = generalDecrypt;

var _decrypt = require("../flattened/decrypt.js");

var _errors = require("../../util/errors.js");

var _is_object = _interopRequireDefault(require("../../lib/is_object.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

async function generalDecrypt(jwe, key, options) {
  if (!(0, _is_object.default)(jwe)) {
    throw new _errors.JWEInvalid('General JWE must be an object');
  }

  if (!Array.isArray(jwe.recipients) || !jwe.recipients.every(_is_object.default)) {
    throw new _errors.JWEInvalid('JWE Recipients missing or incorrect type');
  }

  if (!jwe.recipients.length) {
    throw new _errors.JWEInvalid('JWE Recipients has no members');
  }

  for (const recipient of jwe.recipients) {
    try {
      return await (0, _decrypt.flattenedDecrypt)({
        aad: jwe.aad,
        ciphertext: jwe.ciphertext,
        encrypted_key: recipient.encrypted_key,
        header: recipient.header,
        iv: jwe.iv,
        protected: jwe.protected,
        tag: jwe.tag,
        unprotected: jwe.unprotected
      }, key, options);
    } catch (_a) {}
  }

  throw new _errors.JWEDecryptionFailed();
}

},{"../../lib/is_object.js":89,"../../util/errors.js":124,"../flattened/decrypt.js":53}],56:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.GeneralEncrypt = void 0;

var _encrypt = require("../flattened/encrypt.js");

var _errors = require("../../util/errors.js");

var _cek = _interopRequireDefault(require("../../lib/cek.js"));

var _is_disjoint = _interopRequireDefault(require("../../lib/is_disjoint.js"));

var _encrypt_key_management = _interopRequireDefault(require("../../lib/encrypt_key_management.js"));

var _base64url = require("../../runtime/base64url.js");

var _validate_crit = _interopRequireDefault(require("../../lib/validate_crit.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

class IndividualRecipient {
  constructor(enc, key, options) {
    this.parent = enc;
    this.key = key;
    this.options = options;
  }

  setUnprotectedHeader(unprotectedHeader) {
    if (this.unprotectedHeader) {
      throw new TypeError('setUnprotectedHeader can only be called once');
    }

    this.unprotectedHeader = unprotectedHeader;
    return this;
  }

  addRecipient(...args) {
    return this.parent.addRecipient(...args);
  }

  encrypt(...args) {
    return this.parent.encrypt(...args);
  }

  done() {
    return this.parent;
  }

}

class GeneralEncrypt {
  constructor(plaintext) {
    this._recipients = [];
    this._plaintext = plaintext;
  }

  addRecipient(key, options) {
    const recipient = new IndividualRecipient(this, key, {
      crit: options === null || options === void 0 ? void 0 : options.crit
    });

    this._recipients.push(recipient);

    return recipient;
  }

  setProtectedHeader(protectedHeader) {
    if (this._protectedHeader) {
      throw new TypeError('setProtectedHeader can only be called once');
    }

    this._protectedHeader = protectedHeader;
    return this;
  }

  setSharedUnprotectedHeader(sharedUnprotectedHeader) {
    if (this._unprotectedHeader) {
      throw new TypeError('setSharedUnprotectedHeader can only be called once');
    }

    this._unprotectedHeader = sharedUnprotectedHeader;
    return this;
  }

  setAdditionalAuthenticatedData(aad) {
    this._aad = aad;
    return this;
  }

  async encrypt(options) {
    var _a, _b, _c;

    if (!this._recipients.length) {
      throw new _errors.JWEInvalid('at least one recipient must be added');
    }

    options = {
      deflateRaw: options === null || options === void 0 ? void 0 : options.deflateRaw
    };

    if (this._recipients.length === 1) {
      const [recipient] = this._recipients;
      const flattened = await new _encrypt.FlattenedEncrypt(this._plaintext).setAdditionalAuthenticatedData(this._aad).setProtectedHeader(this._protectedHeader).setSharedUnprotectedHeader(this._unprotectedHeader).setUnprotectedHeader(recipient.unprotectedHeader).encrypt(recipient.key, { ...recipient.options,
        ...options
      });
      let jwe = {
        ciphertext: flattened.ciphertext,
        iv: flattened.iv,
        recipients: [{}],
        tag: flattened.tag
      };
      if (flattened.aad) jwe.aad = flattened.aad;
      if (flattened.protected) jwe.protected = flattened.protected;
      if (flattened.unprotected) jwe.unprotected = flattened.unprotected;
      if (flattened.encrypted_key) jwe.recipients[0].encrypted_key = flattened.encrypted_key;
      if (flattened.header) jwe.recipients[0].header = flattened.header;
      return jwe;
    }

    let enc;

    for (let i = 0; i < this._recipients.length; i++) {
      const recipient = this._recipients[i];

      if (!(0, _is_disjoint.default)(this._protectedHeader, this._unprotectedHeader, recipient.unprotectedHeader)) {
        throw new _errors.JWEInvalid('JWE Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint');
      }

      const joseHeader = { ...this._protectedHeader,
        ...this._unprotectedHeader,
        ...recipient.unprotectedHeader
      };
      const {
        alg
      } = joseHeader;

      if (typeof alg !== 'string' || !alg) {
        throw new _errors.JWEInvalid('JWE "alg" (Algorithm) Header Parameter missing or invalid');
      }

      if (alg === 'dir' || alg === 'ECDH-ES') {
        throw new _errors.JWEInvalid('"dir" and "ECDH-ES" alg may only be used with a single recipient');
      }

      if (typeof joseHeader.enc !== 'string' || !joseHeader.enc) {
        throw new _errors.JWEInvalid('JWE "enc" (Encryption Algorithm) Header Parameter missing or invalid');
      }

      if (!enc) {
        enc = joseHeader.enc;
      } else if (enc !== joseHeader.enc) {
        throw new _errors.JWEInvalid('JWE "enc" (Encryption Algorithm) Header Parameter must be the same for all recipients');
      }

      (0, _validate_crit.default)(_errors.JWEInvalid, new Map(), recipient.options.crit, this._protectedHeader, joseHeader);

      if (joseHeader.zip !== undefined) {
        if (!this._protectedHeader || !this._protectedHeader.zip) {
          throw new _errors.JWEInvalid('JWE "zip" (Compression Algorithm) Header MUST be integrity protected');
        }
      }
    }

    const cek = (0, _cek.default)(enc);
    let jwe = {
      ciphertext: '',
      iv: '',
      recipients: [],
      tag: ''
    };

    for (let i = 0; i < this._recipients.length; i++) {
      const recipient = this._recipients[i];
      const target = {};
      jwe.recipients.push(target);

      if (i === 0) {
        const flattened = await new _encrypt.FlattenedEncrypt(this._plaintext).setAdditionalAuthenticatedData(this._aad).setContentEncryptionKey(cek).setProtectedHeader(this._protectedHeader).setSharedUnprotectedHeader(this._unprotectedHeader).setUnprotectedHeader(recipient.unprotectedHeader).encrypt(recipient.key, { ...recipient.options,
          ...options,
          [_encrypt.unprotected]: true
        });
        jwe.ciphertext = flattened.ciphertext;
        jwe.iv = flattened.iv;
        jwe.tag = flattened.tag;
        if (flattened.aad) jwe.aad = flattened.aad;
        if (flattened.protected) jwe.protected = flattened.protected;
        if (flattened.unprotected) jwe.unprotected = flattened.unprotected;
        target.encrypted_key = flattened.encrypted_key;
        if (flattened.header) target.header = flattened.header;
        continue;
      }

      const {
        encryptedKey,
        parameters
      } = await (0, _encrypt_key_management.default)(((_a = recipient.unprotectedHeader) === null || _a === void 0 ? void 0 : _a.alg) || ((_b = this._protectedHeader) === null || _b === void 0 ? void 0 : _b.alg) || ((_c = this._unprotectedHeader) === null || _c === void 0 ? void 0 : _c.alg), enc, recipient.key, cek);
      target.encrypted_key = (0, _base64url.encode)(encryptedKey);
      if (recipient.unprotectedHeader || parameters) target.header = { ...recipient.unprotectedHeader,
        ...parameters
      };
    }

    return jwe;
  }

}

exports.GeneralEncrypt = GeneralEncrypt;

},{"../../lib/cek.js":78,"../../lib/encrypt_key_management.js":84,"../../lib/is_disjoint.js":88,"../../lib/validate_crit.js":94,"../../runtime/base64url.js":97,"../../util/errors.js":124,"../flattened/encrypt.js":54}],57:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.EmbeddedJWK = EmbeddedJWK;

var _import = require("../key/import.js");

var _is_object = _interopRequireDefault(require("../lib/is_object.js"));

var _errors = require("../util/errors.js");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

async function EmbeddedJWK(protectedHeader, token) {
  const joseHeader = { ...protectedHeader,
    ...token.header
  };

  if (!(0, _is_object.default)(joseHeader.jwk)) {
    throw new _errors.JWSInvalid('"jwk" (JSON Web Key) Header Parameter must be a JSON object');
  }

  const key = await (0, _import.importJWK)({ ...joseHeader.jwk,
    ext: true
  }, joseHeader.alg, true);

  if (key instanceof Uint8Array || key.type !== 'public') {
    throw new _errors.JWSInvalid('"jwk" (JSON Web Key) Header Parameter must be a public key');
  }

  return key;
}

},{"../key/import.js":75,"../lib/is_object.js":89,"../util/errors.js":124}],58:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.calculateJwkThumbprint = calculateJwkThumbprint;

var _digest = _interopRequireDefault(require("../runtime/digest.js"));

var _base64url = require("../runtime/base64url.js");

var _errors = require("../util/errors.js");

var _buffer_utils = require("../lib/buffer_utils.js");

var _is_object = _interopRequireDefault(require("../lib/is_object.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const check = (value, description) => {
  if (typeof value !== 'string' || !value) {
    throw new _errors.JWKInvalid(`${description} missing or invalid`);
  }
};

async function calculateJwkThumbprint(jwk, digestAlgorithm = 'sha256') {
  if (!(0, _is_object.default)(jwk)) {
    throw new TypeError('JWK must be an object');
  }

  let components;

  switch (jwk.kty) {
    case 'EC':
      check(jwk.crv, '"crv" (Curve) Parameter');
      check(jwk.x, '"x" (X Coordinate) Parameter');
      check(jwk.y, '"y" (Y Coordinate) Parameter');
      components = {
        crv: jwk.crv,
        kty: jwk.kty,
        x: jwk.x,
        y: jwk.y
      };
      break;

    case 'OKP':
      check(jwk.crv, '"crv" (Subtype of Key Pair) Parameter');
      check(jwk.x, '"x" (Public Key) Parameter');
      components = {
        crv: jwk.crv,
        kty: jwk.kty,
        x: jwk.x
      };
      break;

    case 'RSA':
      check(jwk.e, '"e" (Exponent) Parameter');
      check(jwk.n, '"n" (Modulus) Parameter');
      components = {
        e: jwk.e,
        kty: jwk.kty,
        n: jwk.n
      };
      break;

    case 'oct':
      check(jwk.k, '"k" (Key Value) Parameter');
      components = {
        k: jwk.k,
        kty: jwk.kty
      };
      break;

    default:
      throw new _errors.JOSENotSupported('"kty" (Key Type) Parameter missing or unsupported');
  }

  const data = _buffer_utils.encoder.encode(JSON.stringify(components));

  return (0, _base64url.encode)(await (0, _digest.default)(digestAlgorithm, data));
}

},{"../lib/buffer_utils.js":77,"../lib/is_object.js":89,"../runtime/base64url.js":97,"../runtime/digest.js":102,"../util/errors.js":124}],59:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.createRemoteJWKSet = createRemoteJWKSet;

var _fetch_jwks = _interopRequireDefault(require("../runtime/fetch_jwks.js"));

var _import = require("../key/import.js");

var _errors = require("../util/errors.js");

var _is_object = _interopRequireDefault(require("../lib/is_object.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function getKtyFromAlg(alg) {
  switch (typeof alg === 'string' && alg.substr(0, 2)) {
    case 'RS':
    case 'PS':
      return 'RSA';

    case 'ES':
      return 'EC';

    case 'Ed':
      return 'OKP';

    default:
      throw new _errors.JOSENotSupported('Unsupported "alg" value for a JSON Web Key Set');
  }
}

function isJWKLike(key) {
  return (0, _is_object.default)(key);
}

class RemoteJWKSet {
  constructor(url, options) {
    this._cached = new WeakMap();

    if (!(url instanceof URL)) {
      throw new TypeError('url must be an instance of URL');
    }

    this._url = new URL(url.href);
    this._options = {
      agent: options === null || options === void 0 ? void 0 : options.agent
    };
    this._timeoutDuration = typeof (options === null || options === void 0 ? void 0 : options.timeoutDuration) === 'number' ? options === null || options === void 0 ? void 0 : options.timeoutDuration : 5000;
    this._cooldownDuration = typeof (options === null || options === void 0 ? void 0 : options.cooldownDuration) === 'number' ? options === null || options === void 0 ? void 0 : options.cooldownDuration : 30000;
  }

  coolingDown() {
    if (!this._cooldownStarted) {
      return false;
    }

    return Date.now() < this._cooldownStarted + this._cooldownDuration;
  }

  async getKey(protectedHeader, token) {
    const joseHeader = { ...protectedHeader,
      ...token.header
    };

    if (!this._jwks) {
      await this.reload();
    }

    const candidates = this._jwks.keys.filter(jwk => {
      let candidate = jwk.kty === getKtyFromAlg(joseHeader.alg);

      if (candidate && typeof joseHeader.kid === 'string') {
        candidate = joseHeader.kid === jwk.kid;
      }

      if (candidate && typeof jwk.alg === 'string') {
        candidate = joseHeader.alg === jwk.alg;
      }

      if (candidate && typeof jwk.use === 'string') {
        candidate = jwk.use === 'sig';
      }

      if (candidate && Array.isArray(jwk.key_ops)) {
        candidate = jwk.key_ops.includes('verify');
      }

      if (candidate && joseHeader.alg === 'EdDSA') {
        candidate = jwk.crv === 'Ed25519' || jwk.crv === 'Ed448';
      }

      if (candidate) {
        switch (joseHeader.alg) {
          case 'ES256':
            candidate = jwk.crv === 'P-256';
            break;

          case 'ES256K':
            candidate = jwk.crv === 'secp256k1';
            break;

          case 'ES384':
            candidate = jwk.crv === 'P-384';
            break;

          case 'ES512':
            candidate = jwk.crv === 'P-521';
            break;

          default:
        }
      }

      return candidate;
    });

    const {
      0: jwk,
      length
    } = candidates;

    if (length === 0) {
      if (this.coolingDown() === false) {
        await this.reload();
        return this.getKey(protectedHeader, token);
      }

      throw new _errors.JWKSNoMatchingKey();
    } else if (length !== 1) {
      throw new _errors.JWKSMultipleMatchingKeys();
    }

    const cached = this._cached.get(jwk) || this._cached.set(jwk, {}).get(jwk);

    if (cached[joseHeader.alg] === undefined) {
      const keyObject = await (0, _import.importJWK)({ ...jwk,
        ext: true
      }, joseHeader.alg);

      if (keyObject instanceof Uint8Array || keyObject.type !== 'public') {
        throw new _errors.JWKSInvalid('JSON Web Key Set members must be public keys');
      }

      cached[joseHeader.alg] = keyObject;
    }

    return cached[joseHeader.alg];
  }

  async reload() {
    if (!this._pendingFetch) {
      this._pendingFetch = (0, _fetch_jwks.default)(this._url, this._timeoutDuration, this._options).then(json => {
        if (typeof json !== 'object' || !json || !Array.isArray(json.keys) || !json.keys.every(isJWKLike)) {
          throw new _errors.JWKSInvalid('JSON Web Key Set malformed');
        }

        this._jwks = {
          keys: json.keys
        };
        this._cooldownStarted = Date.now();
        this._pendingFetch = undefined;
      }).catch(err => {
        this._pendingFetch = undefined;
        throw err;
      });
    }

    await this._pendingFetch;
  }

}

function createRemoteJWKSet(url, options) {
  return RemoteJWKSet.prototype.getKey.bind(new RemoteJWKSet(url, options));
}

},{"../key/import.js":75,"../lib/is_object.js":89,"../runtime/fetch_jwks.js":106,"../util/errors.js":124}],60:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.CompactSign = void 0;

var _sign = require("../flattened/sign.js");

class CompactSign {
  constructor(payload) {
    this._flattened = new _sign.FlattenedSign(payload);
  }

  setProtectedHeader(protectedHeader) {
    this._flattened.setProtectedHeader(protectedHeader);

    return this;
  }

  async sign(key, options) {
    const jws = await this._flattened.sign(key, options);

    if (jws.payload === undefined) {
      throw new TypeError('use the flattened module for creating JWS with b64: false');
    }

    return `${jws.protected}.${jws.payload}.${jws.signature}`;
  }

}

exports.CompactSign = CompactSign;

},{"../flattened/sign.js":62}],61:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.compactVerify = compactVerify;

var _verify = require("../flattened/verify.js");

var _errors = require("../../util/errors.js");

var _buffer_utils = require("../../lib/buffer_utils.js");

async function compactVerify(jws, key, options) {
  if (jws instanceof Uint8Array) {
    jws = _buffer_utils.decoder.decode(jws);
  }

  if (typeof jws !== 'string') {
    throw new _errors.JWSInvalid('Compact JWS must be a string or Uint8Array');
  }

  const {
    0: protectedHeader,
    1: payload,
    2: signature,
    length
  } = jws.split('.');

  if (length !== 3) {
    throw new _errors.JWSInvalid('Invalid Compact JWS');
  }

  const verified = await (0, _verify.flattenedVerify)({
    payload,
    protected: protectedHeader,
    signature
  }, key, options);
  const result = {
    payload: verified.payload,
    protectedHeader: verified.protectedHeader
  };

  if (typeof key === 'function') {
    return { ...result,
      key: verified.key
    };
  }

  return result;
}

},{"../../lib/buffer_utils.js":77,"../../util/errors.js":124,"../flattened/verify.js":63}],62:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.FlattenedSign = void 0;

var _base64url = require("../../runtime/base64url.js");

var _sign = _interopRequireDefault(require("../../runtime/sign.js"));

var _is_disjoint = _interopRequireDefault(require("../../lib/is_disjoint.js"));

var _errors = require("../../util/errors.js");

var _buffer_utils = require("../../lib/buffer_utils.js");

var _check_key_type = _interopRequireDefault(require("../../lib/check_key_type.js"));

var _validate_crit = _interopRequireDefault(require("../../lib/validate_crit.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

class FlattenedSign {
  constructor(payload) {
    if (!(payload instanceof Uint8Array)) {
      throw new TypeError('payload must be an instance of Uint8Array');
    }

    this._payload = payload;
  }

  setProtectedHeader(protectedHeader) {
    if (this._protectedHeader) {
      throw new TypeError('setProtectedHeader can only be called once');
    }

    this._protectedHeader = protectedHeader;
    return this;
  }

  setUnprotectedHeader(unprotectedHeader) {
    if (this._unprotectedHeader) {
      throw new TypeError('setUnprotectedHeader can only be called once');
    }

    this._unprotectedHeader = unprotectedHeader;
    return this;
  }

  async sign(key, options) {
    if (!this._protectedHeader && !this._unprotectedHeader) {
      throw new _errors.JWSInvalid('either setProtectedHeader or setUnprotectedHeader must be called before #sign()');
    }

    if (!(0, _is_disjoint.default)(this._protectedHeader, this._unprotectedHeader)) {
      throw new _errors.JWSInvalid('JWS Protected and JWS Unprotected Header Parameter names must be disjoint');
    }

    const joseHeader = { ...this._protectedHeader,
      ...this._unprotectedHeader
    };
    const extensions = (0, _validate_crit.default)(_errors.JWSInvalid, new Map([['b64', true]]), options === null || options === void 0 ? void 0 : options.crit, this._protectedHeader, joseHeader);
    let b64 = true;

    if (extensions.has('b64')) {
      b64 = this._protectedHeader.b64;

      if (typeof b64 !== 'boolean') {
        throw new _errors.JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
      }
    }

    const {
      alg
    } = joseHeader;

    if (typeof alg !== 'string' || !alg) {
      throw new _errors.JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
    }

    (0, _check_key_type.default)(alg, key, 'sign');
    let payload = this._payload;

    if (b64) {
      payload = _buffer_utils.encoder.encode((0, _base64url.encode)(payload));
    }

    let protectedHeader;

    if (this._protectedHeader) {
      protectedHeader = _buffer_utils.encoder.encode((0, _base64url.encode)(JSON.stringify(this._protectedHeader)));
    } else {
      protectedHeader = _buffer_utils.encoder.encode('');
    }

    const data = (0, _buffer_utils.concat)(protectedHeader, _buffer_utils.encoder.encode('.'), payload);
    const signature = await (0, _sign.default)(alg, key, data);
    const jws = {
      signature: (0, _base64url.encode)(signature),
      payload: ''
    };

    if (b64) {
      jws.payload = _buffer_utils.decoder.decode(payload);
    }

    if (this._unprotectedHeader) {
      jws.header = this._unprotectedHeader;
    }

    if (this._protectedHeader) {
      jws.protected = _buffer_utils.decoder.decode(protectedHeader);
    }

    return jws;
  }

}

exports.FlattenedSign = FlattenedSign;

},{"../../lib/buffer_utils.js":77,"../../lib/check_key_type.js":80,"../../lib/is_disjoint.js":88,"../../lib/validate_crit.js":94,"../../runtime/base64url.js":97,"../../runtime/sign.js":115,"../../util/errors.js":124}],63:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.flattenedVerify = flattenedVerify;

var _base64url = require("../../runtime/base64url.js");

var _verify = _interopRequireDefault(require("../../runtime/verify.js"));

var _errors = require("../../util/errors.js");

var _buffer_utils = require("../../lib/buffer_utils.js");

var _is_disjoint = _interopRequireDefault(require("../../lib/is_disjoint.js"));

var _is_object = _interopRequireDefault(require("../../lib/is_object.js"));

var _check_key_type = _interopRequireDefault(require("../../lib/check_key_type.js"));

var _validate_crit = _interopRequireDefault(require("../../lib/validate_crit.js"));

var _validate_algorithms = _interopRequireDefault(require("../../lib/validate_algorithms.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

async function flattenedVerify(jws, key, options) {
  var _a;

  if (!(0, _is_object.default)(jws)) {
    throw new _errors.JWSInvalid('Flattened JWS must be an object');
  }

  if (jws.protected === undefined && jws.header === undefined) {
    throw new _errors.JWSInvalid('Flattened JWS must have either of the "protected" or "header" members');
  }

  if (jws.protected !== undefined && typeof jws.protected !== 'string') {
    throw new _errors.JWSInvalid('JWS Protected Header incorrect type');
  }

  if (jws.payload === undefined) {
    throw new _errors.JWSInvalid('JWS Payload missing');
  }

  if (typeof jws.signature !== 'string') {
    throw new _errors.JWSInvalid('JWS Signature missing or incorrect type');
  }

  if (jws.header !== undefined && !(0, _is_object.default)(jws.header)) {
    throw new _errors.JWSInvalid('JWS Unprotected Header incorrect type');
  }

  let parsedProt = {};

  if (jws.protected) {
    const protectedHeader = (0, _base64url.decode)(jws.protected);

    try {
      parsedProt = JSON.parse(_buffer_utils.decoder.decode(protectedHeader));
    } catch (_b) {
      throw new _errors.JWSInvalid('JWS Protected Header is invalid');
    }
  }

  if (!(0, _is_disjoint.default)(parsedProt, jws.header)) {
    throw new _errors.JWSInvalid('JWS Protected and JWS Unprotected Header Parameter names must be disjoint');
  }

  const joseHeader = { ...parsedProt,
    ...jws.header
  };
  const extensions = (0, _validate_crit.default)(_errors.JWSInvalid, new Map([['b64', true]]), options === null || options === void 0 ? void 0 : options.crit, parsedProt, joseHeader);
  let b64 = true;

  if (extensions.has('b64')) {
    b64 = parsedProt.b64;

    if (typeof b64 !== 'boolean') {
      throw new _errors.JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
    }
  }

  const {
    alg
  } = joseHeader;

  if (typeof alg !== 'string' || !alg) {
    throw new _errors.JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
  }

  const algorithms = options && (0, _validate_algorithms.default)('algorithms', options.algorithms);

  if (algorithms && !algorithms.has(alg)) {
    throw new _errors.JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter not allowed');
  }

  if (b64) {
    if (typeof jws.payload !== 'string') {
      throw new _errors.JWSInvalid('JWS Payload must be a string');
    }
  } else if (typeof jws.payload !== 'string' && !(jws.payload instanceof Uint8Array)) {
    throw new _errors.JWSInvalid('JWS Payload must be a string or an Uint8Array instance');
  }

  let resolvedKey = false;

  if (typeof key === 'function') {
    key = await key(parsedProt, jws);
    resolvedKey = true;
  }

  (0, _check_key_type.default)(alg, key, 'verify');
  const data = (0, _buffer_utils.concat)(_buffer_utils.encoder.encode((_a = jws.protected) !== null && _a !== void 0 ? _a : ''), _buffer_utils.encoder.encode('.'), typeof jws.payload === 'string' ? _buffer_utils.encoder.encode(jws.payload) : jws.payload);
  const signature = (0, _base64url.decode)(jws.signature);
  const verified = await (0, _verify.default)(alg, key, signature, data);

  if (!verified) {
    throw new _errors.JWSSignatureVerificationFailed();
  }

  let payload;

  if (b64) {
    payload = (0, _base64url.decode)(jws.payload);
  } else if (typeof jws.payload === 'string') {
    payload = _buffer_utils.encoder.encode(jws.payload);
  } else {
    payload = jws.payload;
  }

  const result = {
    payload
  };

  if (jws.protected !== undefined) {
    result.protectedHeader = parsedProt;
  }

  if (jws.header !== undefined) {
    result.unprotectedHeader = jws.header;
  }

  if (resolvedKey) {
    return { ...result,
      key
    };
  }

  return result;
}

},{"../../lib/buffer_utils.js":77,"../../lib/check_key_type.js":80,"../../lib/is_disjoint.js":88,"../../lib/is_object.js":89,"../../lib/validate_algorithms.js":93,"../../lib/validate_crit.js":94,"../../runtime/base64url.js":97,"../../runtime/verify.js":119,"../../util/errors.js":124}],64:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.GeneralSign = void 0;

var _sign = require("../flattened/sign.js");

var _errors = require("../../util/errors.js");

class IndividualSignature {
  constructor(sig, key, options) {
    this.parent = sig;
    this.key = key;
    this.options = options;
  }

  setProtectedHeader(protectedHeader) {
    if (this.protectedHeader) {
      throw new TypeError('setProtectedHeader can only be called once');
    }

    this.protectedHeader = protectedHeader;
    return this;
  }

  setUnprotectedHeader(unprotectedHeader) {
    if (this.unprotectedHeader) {
      throw new TypeError('setUnprotectedHeader can only be called once');
    }

    this.unprotectedHeader = unprotectedHeader;
    return this;
  }

  addSignature(...args) {
    return this.parent.addSignature(...args);
  }

  sign(...args) {
    return this.parent.sign(...args);
  }

  done() {
    return this.parent;
  }

}

class GeneralSign {
  constructor(payload) {
    this._signatures = [];
    this._payload = payload;
  }

  addSignature(key, options) {
    const signature = new IndividualSignature(this, key, options);

    this._signatures.push(signature);

    return signature;
  }

  async sign() {
    if (!this._signatures.length) {
      throw new _errors.JWSInvalid('at least one signature must be added');
    }

    const jws = {
      signatures: [],
      payload: ''
    };

    for (let i = 0; i < this._signatures.length; i++) {
      const signature = this._signatures[i];
      const flattened = new _sign.FlattenedSign(this._payload);
      flattened.setProtectedHeader(signature.protectedHeader);
      flattened.setUnprotectedHeader(signature.unprotectedHeader);
      const {
        payload,
        ...rest
      } = await flattened.sign(signature.key, signature.options);

      if (i === 0) {
        jws.payload = payload;
      } else if (jws.payload !== payload) {
        throw new _errors.JWSInvalid('inconsistent use of JWS Unencoded Payload Option (RFC7797)');
      }

      jws.signatures.push(rest);
    }

    return jws;
  }

}

exports.GeneralSign = GeneralSign;

},{"../../util/errors.js":124,"../flattened/sign.js":62}],65:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.generalVerify = generalVerify;

var _verify = require("../flattened/verify.js");

var _errors = require("../../util/errors.js");

var _is_object = _interopRequireDefault(require("../../lib/is_object.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

async function generalVerify(jws, key, options) {
  if (!(0, _is_object.default)(jws)) {
    throw new _errors.JWSInvalid('General JWS must be an object');
  }

  if (!Array.isArray(jws.signatures) || !jws.signatures.every(_is_object.default)) {
    throw new _errors.JWSInvalid('JWS Signatures missing or incorrect type');
  }

  for (const signature of jws.signatures) {
    try {
      return await (0, _verify.flattenedVerify)({
        header: signature.header,
        payload: jws.payload,
        protected: signature.protected,
        signature: signature.signature
      }, key, options);
    } catch (_a) {}
  }

  throw new _errors.JWSSignatureVerificationFailed();
}

},{"../../lib/is_object.js":89,"../../util/errors.js":124,"../flattened/verify.js":63}],66:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.jwtDecrypt = jwtDecrypt;

var _decrypt = require("../jwe/compact/decrypt.js");

var _jwt_claims_set = _interopRequireDefault(require("../lib/jwt_claims_set.js"));

var _errors = require("../util/errors.js");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

async function jwtDecrypt(jwt, key, options) {
  const decrypted = await (0, _decrypt.compactDecrypt)(jwt, key, options);
  const payload = (0, _jwt_claims_set.default)(decrypted.protectedHeader, decrypted.plaintext, options);
  const {
    protectedHeader
  } = decrypted;

  if (protectedHeader.iss !== undefined && protectedHeader.iss !== payload.iss) {
    throw new _errors.JWTClaimValidationFailed('replicated "iss" claim header parameter mismatch', 'iss', 'mismatch');
  }

  if (protectedHeader.sub !== undefined && protectedHeader.sub !== payload.sub) {
    throw new _errors.JWTClaimValidationFailed('replicated "sub" claim header parameter mismatch', 'sub', 'mismatch');
  }

  if (protectedHeader.aud !== undefined && JSON.stringify(protectedHeader.aud) !== JSON.stringify(payload.aud)) {
    throw new _errors.JWTClaimValidationFailed('replicated "aud" claim header parameter mismatch', 'aud', 'mismatch');
  }

  const result = {
    payload,
    protectedHeader
  };

  if (typeof key === 'function') {
    return { ...result,
      key: decrypted.key
    };
  }

  return result;
}

},{"../jwe/compact/decrypt.js":51,"../lib/jwt_claims_set.js":91,"../util/errors.js":124}],67:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.EncryptJWT = void 0;

var _encrypt = require("../jwe/compact/encrypt.js");

var _buffer_utils = require("../lib/buffer_utils.js");

var _produce = require("./produce.js");

class EncryptJWT extends _produce.ProduceJWT {
  setProtectedHeader(protectedHeader) {
    if (this._protectedHeader) {
      throw new TypeError('setProtectedHeader can only be called once');
    }

    this._protectedHeader = protectedHeader;
    return this;
  }

  setKeyManagementParameters(parameters) {
    if (this._keyManagementParameters) {
      throw new TypeError('setKeyManagementParameters can only be called once');
    }

    this._keyManagementParameters = parameters;
    return this;
  }

  setContentEncryptionKey(cek) {
    if (this._cek) {
      throw new TypeError('setContentEncryptionKey can only be called once');
    }

    this._cek = cek;
    return this;
  }

  setInitializationVector(iv) {
    if (this._iv) {
      throw new TypeError('setInitializationVector can only be called once');
    }

    this._iv = iv;
    return this;
  }

  replicateIssuerAsHeader() {
    this._replicateIssuerAsHeader = true;
    return this;
  }

  replicateSubjectAsHeader() {
    this._replicateSubjectAsHeader = true;
    return this;
  }

  replicateAudienceAsHeader() {
    this._replicateAudienceAsHeader = true;
    return this;
  }

  async encrypt(key, options) {
    const enc = new _encrypt.CompactEncrypt(_buffer_utils.encoder.encode(JSON.stringify(this._payload)));

    if (this._replicateIssuerAsHeader) {
      this._protectedHeader = { ...this._protectedHeader,
        iss: this._payload.iss
      };
    }

    if (this._replicateSubjectAsHeader) {
      this._protectedHeader = { ...this._protectedHeader,
        sub: this._payload.sub
      };
    }

    if (this._replicateAudienceAsHeader) {
      this._protectedHeader = { ...this._protectedHeader,
        aud: this._payload.aud
      };
    }

    enc.setProtectedHeader(this._protectedHeader);

    if (this._iv) {
      enc.setInitializationVector(this._iv);
    }

    if (this._cek) {
      enc.setContentEncryptionKey(this._cek);
    }

    if (this._keyManagementParameters) {
      enc.setKeyManagementParameters(this._keyManagementParameters);
    }

    return enc.encrypt(key, options);
  }

}

exports.EncryptJWT = EncryptJWT;

},{"../jwe/compact/encrypt.js":52,"../lib/buffer_utils.js":77,"./produce.js":68}],68:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.ProduceJWT = void 0;

var _epoch = _interopRequireDefault(require("../lib/epoch.js"));

var _is_object = _interopRequireDefault(require("../lib/is_object.js"));

var _secs = _interopRequireDefault(require("../lib/secs.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

class ProduceJWT {
  constructor(payload) {
    if (!(0, _is_object.default)(payload)) {
      throw new TypeError('JWT Claims Set MUST be an object');
    }

    this._payload = payload;
  }

  setIssuer(issuer) {
    this._payload = { ...this._payload,
      iss: issuer
    };
    return this;
  }

  setSubject(subject) {
    this._payload = { ...this._payload,
      sub: subject
    };
    return this;
  }

  setAudience(audience) {
    this._payload = { ...this._payload,
      aud: audience
    };
    return this;
  }

  setJti(jwtId) {
    this._payload = { ...this._payload,
      jti: jwtId
    };
    return this;
  }

  setNotBefore(input) {
    if (typeof input === 'number') {
      this._payload = { ...this._payload,
        nbf: input
      };
    } else {
      this._payload = { ...this._payload,
        nbf: (0, _epoch.default)(new Date()) + (0, _secs.default)(input)
      };
    }

    return this;
  }

  setExpirationTime(input) {
    if (typeof input === 'number') {
      this._payload = { ...this._payload,
        exp: input
      };
    } else {
      this._payload = { ...this._payload,
        exp: (0, _epoch.default)(new Date()) + (0, _secs.default)(input)
      };
    }

    return this;
  }

  setIssuedAt(input) {
    if (typeof input === 'undefined') {
      this._payload = { ...this._payload,
        iat: (0, _epoch.default)(new Date())
      };
    } else {
      this._payload = { ...this._payload,
        iat: input
      };
    }

    return this;
  }

}

exports.ProduceJWT = ProduceJWT;

},{"../lib/epoch.js":85,"../lib/is_object.js":89,"../lib/secs.js":92}],69:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.SignJWT = void 0;

var _sign = require("../jws/compact/sign.js");

var _errors = require("../util/errors.js");

var _buffer_utils = require("../lib/buffer_utils.js");

var _produce = require("./produce.js");

class SignJWT extends _produce.ProduceJWT {
  setProtectedHeader(protectedHeader) {
    this._protectedHeader = protectedHeader;
    return this;
  }

  async sign(key, options) {
    var _a;

    const sig = new _sign.CompactSign(_buffer_utils.encoder.encode(JSON.stringify(this._payload)));
    sig.setProtectedHeader(this._protectedHeader);

    if (Array.isArray((_a = this._protectedHeader) === null || _a === void 0 ? void 0 : _a.crit) && this._protectedHeader.crit.includes('b64') && this._protectedHeader.b64 === false) {
      throw new _errors.JWTInvalid('JWTs MUST NOT use unencoded payload');
    }

    return sig.sign(key, options);
  }

}

exports.SignJWT = SignJWT;

},{"../jws/compact/sign.js":60,"../lib/buffer_utils.js":77,"../util/errors.js":124,"./produce.js":68}],70:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.UnsecuredJWT = void 0;

var base64url = _interopRequireWildcard(require("../runtime/base64url.js"));

var _buffer_utils = require("../lib/buffer_utils.js");

var _errors = require("../util/errors.js");

var _jwt_claims_set = _interopRequireDefault(require("../lib/jwt_claims_set.js"));

var _produce = require("./produce.js");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

class UnsecuredJWT extends _produce.ProduceJWT {
  encode() {
    const header = base64url.encode(JSON.stringify({
      alg: 'none'
    }));
    const payload = base64url.encode(JSON.stringify(this._payload));
    return `${header}.${payload}.`;
  }

  static decode(jwt, options) {
    if (typeof jwt !== 'string') {
      throw new _errors.JWTInvalid('Unsecured JWT must be a string');
    }

    const {
      0: encodedHeader,
      1: encodedPayload,
      2: signature,
      length
    } = jwt.split('.');

    if (length !== 3 || signature !== '') {
      throw new _errors.JWTInvalid('Invalid Unsecured JWT');
    }

    let header;

    try {
      header = JSON.parse(_buffer_utils.decoder.decode(base64url.decode(encodedHeader)));
      if (header.alg !== 'none') throw new Error();
    } catch (_a) {
      throw new _errors.JWTInvalid('Invalid Unsecured JWT');
    }

    const payload = (0, _jwt_claims_set.default)(header, base64url.decode(encodedPayload), options);
    return {
      payload,
      header
    };
  }

}

exports.UnsecuredJWT = UnsecuredJWT;

},{"../lib/buffer_utils.js":77,"../lib/jwt_claims_set.js":91,"../runtime/base64url.js":97,"../util/errors.js":124,"./produce.js":68}],71:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.jwtVerify = jwtVerify;

var _verify = require("../jws/compact/verify.js");

var _jwt_claims_set = _interopRequireDefault(require("../lib/jwt_claims_set.js"));

var _errors = require("../util/errors.js");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

async function jwtVerify(jwt, key, options) {
  var _a;

  const verified = await (0, _verify.compactVerify)(jwt, key, options);

  if (((_a = verified.protectedHeader.crit) === null || _a === void 0 ? void 0 : _a.includes('b64')) && verified.protectedHeader.b64 === false) {
    throw new _errors.JWTInvalid('JWTs MUST NOT use unencoded payload');
  }

  const payload = (0, _jwt_claims_set.default)(verified.protectedHeader, verified.payload, options);
  const result = {
    payload,
    protectedHeader: verified.protectedHeader
  };

  if (typeof key === 'function') {
    return { ...result,
      key: verified.key
    };
  }

  return result;
}

},{"../jws/compact/verify.js":61,"../lib/jwt_claims_set.js":91,"../util/errors.js":124}],72:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.exportJWK = exportJWK;
exports.exportPKCS8 = exportPKCS8;
exports.exportSPKI = exportSPKI;

var _asn = require("../runtime/asn1.js");

var _key_to_jwk = _interopRequireDefault(require("../runtime/key_to_jwk.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

async function exportSPKI(key) {
  return (0, _asn.toSPKI)(key);
}

async function exportPKCS8(key) {
  return (0, _asn.toPKCS8)(key);
}

async function exportJWK(key) {
  return (0, _key_to_jwk.default)(key);
}

},{"../runtime/asn1.js":96,"../runtime/key_to_jwk.js":111}],73:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.generateKeyPair = generateKeyPair;

var _generate = require("../runtime/generate.js");

async function generateKeyPair(alg, options) {
  return (0, _generate.generateKeyPair)(alg, options);
}

},{"../runtime/generate.js":107}],74:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.generateSecret = generateSecret;

var _generate = require("../runtime/generate.js");

async function generateSecret(alg, options) {
  return (0, _generate.generateSecret)(alg, options);
}

},{"../runtime/generate.js":107}],75:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.importJWK = importJWK;
exports.importPKCS8 = importPKCS8;
exports.importSPKI = importSPKI;
exports.importX509 = importX509;

var _base64url = require("../runtime/base64url.js");

var _asn = require("../runtime/asn1.js");

var _jwk_to_key = _interopRequireDefault(require("../runtime/jwk_to_key.js"));

var _errors = require("../util/errors.js");

var _format_pem = _interopRequireDefault(require("../lib/format_pem.js"));

var _is_object = _interopRequireDefault(require("../lib/is_object.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function getElement(seq) {
  let result = [];
  let next = 0;

  while (next < seq.length) {
    let nextPart = parseElement(seq.subarray(next));
    result.push(nextPart);
    next += nextPart.byteLength;
  }

  return result;
}

function parseElement(bytes) {
  let position = 0;
  let tag = bytes[0] & 0x1f;
  position++;

  if (tag === 0x1f) {
    tag = 0;

    while (bytes[position] >= 0x80) {
      tag = tag * 128 + bytes[position] - 0x80;
      position++;
    }

    tag = tag * 128 + bytes[position] - 0x80;
    position++;
  }

  let length = 0;

  if (bytes[position] < 0x80) {
    length = bytes[position];
    position++;
  } else {
    let numberOfDigits = bytes[position] & 0x7f;
    position++;
    length = 0;

    for (let i = 0; i < numberOfDigits; i++) {
      length = length * 256 + bytes[position];
      position++;
    }
  }

  if (length === 0x80) {
    length = 0;

    while (bytes[position + length] !== 0 || bytes[position + length + 1] !== 0) {
      length++;
    }

    const byteLength = position + length + 2;
    return {
      byteLength,
      contents: bytes.subarray(position, position + length),
      raw: bytes.subarray(0, byteLength)
    };
  }

  const byteLength = position + length;
  return {
    byteLength,
    contents: bytes.subarray(position, byteLength),
    raw: bytes.subarray(0, byteLength)
  };
}

function spkiFromX509(buf) {
  const tbsCertificate = getElement(getElement(parseElement(buf).contents)[0].contents);
  return (0, _base64url.encodeBase64)(tbsCertificate[tbsCertificate[0].raw[0] === 0xa0 ? 6 : 5].raw);
}

function getSPKI(x509) {
  const pem = x509.replace(/(?:-----(?:BEGIN|END) CERTIFICATE-----|\s)/g, '');
  const raw = (0, _base64url.decodeBase64)(pem);
  return (0, _format_pem.default)(spkiFromX509(raw), 'PUBLIC KEY');
}

async function importSPKI(spki, alg, options) {
  if (typeof spki !== 'string' || spki.indexOf('-----BEGIN PUBLIC KEY-----') !== 0) {
    throw new TypeError('"spki" must be SPKI formatted string');
  }

  return (0, _asn.fromSPKI)(spki, alg, options);
}

async function importX509(x509, alg, options) {
  if (typeof x509 !== 'string' || x509.indexOf('-----BEGIN CERTIFICATE-----') !== 0) {
    throw new TypeError('"x509" must be X.509 formatted string');
  }

  const spki = getSPKI(x509);
  return (0, _asn.fromSPKI)(spki, alg, options);
}

async function importPKCS8(pkcs8, alg, options) {
  if (typeof pkcs8 !== 'string' || pkcs8.indexOf('-----BEGIN PRIVATE KEY-----') !== 0) {
    throw new TypeError('"pkcs8" must be PCKS8 formatted string');
  }

  return (0, _asn.fromPKCS8)(pkcs8, alg, options);
}

async function importJWK(jwk, alg, octAsKeyObject) {
  if (!(0, _is_object.default)(jwk)) {
    throw new TypeError('JWK must be an object');
  }

  alg || (alg = jwk.alg);

  if (typeof alg !== 'string' || !alg) {
    throw new TypeError('"alg" argument is required when "jwk.alg" is not present');
  }

  switch (jwk.kty) {
    case 'oct':
      if (typeof jwk.k !== 'string' || !jwk.k) {
        throw new TypeError('missing "k" (Key Value) Parameter value');
      }

      octAsKeyObject !== null && octAsKeyObject !== void 0 ? octAsKeyObject : octAsKeyObject = jwk.ext !== true;

      if (octAsKeyObject) {
        return (0, _jwk_to_key.default)({ ...jwk,
          alg,
          ext: false
        });
      }

      return (0, _base64url.decode)(jwk.k);

    case 'RSA':
      if (jwk.oth !== undefined) {
        throw new _errors.JOSENotSupported('RSA JWK "oth" (Other Primes Info) Parameter value is not supported');
      }

    case 'EC':
    case 'OKP':
      return (0, _jwk_to_key.default)({ ...jwk,
        alg
      });

    default:
      throw new _errors.JOSENotSupported('Unsupported "kty" (Key Type) Parameter value');
  }
}

},{"../lib/format_pem.js":86,"../lib/is_object.js":89,"../runtime/asn1.js":96,"../runtime/base64url.js":97,"../runtime/jwk_to_key.js":110,"../util/errors.js":124}],76:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.unwrap = unwrap;
exports.wrap = wrap;

var _encrypt = _interopRequireDefault(require("../runtime/encrypt.js"));

var _decrypt = _interopRequireDefault(require("../runtime/decrypt.js"));

var _iv = _interopRequireDefault(require("./iv.js"));

var _base64url = require("../runtime/base64url.js");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

async function wrap(alg, key, cek, iv) {
  const jweAlgorithm = alg.substr(0, 7);
  iv || (iv = (0, _iv.default)(jweAlgorithm));
  const {
    ciphertext: encryptedKey,
    tag
  } = await (0, _encrypt.default)(jweAlgorithm, cek, key, iv, new Uint8Array(0));
  return {
    encryptedKey,
    iv: (0, _base64url.encode)(iv),
    tag: (0, _base64url.encode)(tag)
  };
}

async function unwrap(alg, key, encryptedKey, iv, tag) {
  const jweAlgorithm = alg.substr(0, 7);
  return (0, _decrypt.default)(jweAlgorithm, key, encryptedKey, iv, tag, new Uint8Array(0));
}

},{"../runtime/base64url.js":97,"../runtime/decrypt.js":101,"../runtime/encrypt.js":104,"./iv.js":90}],77:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.concat = concat;
exports.concatKdf = concatKdf;
exports.encoder = exports.decoder = void 0;
exports.lengthAndInput = lengthAndInput;
exports.p2s = p2s;
exports.uint32be = uint32be;
exports.uint64be = uint64be;
const encoder = new TextEncoder();
exports.encoder = encoder;
const decoder = new TextDecoder();
exports.decoder = decoder;
const MAX_INT32 = 2 ** 32;

function concat(...buffers) {
  const size = buffers.reduce((acc, {
    length
  }) => acc + length, 0);
  const buf = new Uint8Array(size);
  let i = 0;
  buffers.forEach(buffer => {
    buf.set(buffer, i);
    i += buffer.length;
  });
  return buf;
}

function p2s(alg, p2sInput) {
  return concat(encoder.encode(alg), new Uint8Array([0]), p2sInput);
}

function writeUInt32BE(buf, value, offset) {
  if (value < 0 || value >= MAX_INT32) {
    throw new RangeError(`value must be >= 0 and <= ${MAX_INT32 - 1}. Received ${value}`);
  }

  buf.set([value >>> 24, value >>> 16, value >>> 8, value & 0xff], offset);
}

function uint64be(value) {
  const high = Math.floor(value / MAX_INT32);
  const low = value % MAX_INT32;
  const buf = new Uint8Array(8);
  writeUInt32BE(buf, high, 0);
  writeUInt32BE(buf, low, 4);
  return buf;
}

function uint32be(value) {
  const buf = new Uint8Array(4);
  writeUInt32BE(buf, value);
  return buf;
}

function lengthAndInput(input) {
  return concat(uint32be(input.length), input);
}

async function concatKdf(digest, secret, bits, value) {
  const iterations = Math.ceil((bits >> 3) / 32);
  let res;

  for (let iter = 1; iter <= iterations; iter++) {
    const buf = new Uint8Array(4 + secret.length + value.length);
    buf.set(uint32be(iter));
    buf.set(secret, 4);
    buf.set(value, 4 + secret.length);

    if (!res) {
      res = await digest('sha256', buf);
    } else {
      res = concat(res, await digest('sha256', buf));
    }
  }

  res = res.slice(0, bits >> 3);
  return res;
}

},{}],78:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.bitLength = bitLength;
exports.default = void 0;

var _errors = require("../util/errors.js");

var _random = _interopRequireDefault(require("../runtime/random.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function bitLength(alg) {
  switch (alg) {
    case 'A128GCM':
      return 128;

    case 'A192GCM':
      return 192;

    case 'A256GCM':
    case 'A128CBC-HS256':
      return 256;

    case 'A192CBC-HS384':
      return 384;

    case 'A256CBC-HS512':
      return 512;

    default:
      throw new _errors.JOSENotSupported(`Unsupported JWE Algorithm: ${alg}`);
  }
}

var _default = alg => (0, _random.default)(new Uint8Array(bitLength(alg) >> 3));

exports.default = _default;

},{"../runtime/random.js":113,"../util/errors.js":124}],79:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _errors = require("../util/errors.js");

var _iv = require("./iv.js");

const checkIvLength = (enc, iv) => {
  if (iv.length << 3 !== (0, _iv.bitLength)(enc)) {
    throw new _errors.JWEInvalid('Invalid Initialization Vector length');
  }
};

var _default = checkIvLength;
exports.default = _default;

},{"../util/errors.js":124,"./iv.js":90}],80:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _invalid_key_input = _interopRequireDefault(require("./invalid_key_input.js"));

var _is_key_like = _interopRequireWildcard(require("../runtime/is_key_like.js"));

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const symmetricTypeCheck = key => {
  if (key instanceof Uint8Array) return;

  if (!(0, _is_key_like.default)(key)) {
    throw new TypeError((0, _invalid_key_input.default)(key, ..._is_key_like.types, 'Uint8Array'));
  }

  if (key.type !== 'secret') {
    throw new TypeError(`${_is_key_like.types.join(' or ')} instances for symmetric algorithms must be of type "secret"`);
  }
};

const asymmetricTypeCheck = (key, usage) => {
  if (!(0, _is_key_like.default)(key)) {
    throw new TypeError((0, _invalid_key_input.default)(key, ..._is_key_like.types));
  }

  if (key.type === 'secret') {
    throw new TypeError(`${_is_key_like.types.join(' or ')} instances for asymmetric algorithms must not be of type "secret"`);
  }

  if (usage === 'sign' && key.type === 'public') {
    throw new TypeError(`${_is_key_like.types.join(' or ')} instances for asymmetric algorithm signing must be of type "private"`);
  }

  if (usage === 'decrypt' && key.type === 'public') {
    throw new TypeError(`${_is_key_like.types.join(' or ')} instances for asymmetric algorithm decryption must be of type "private"`);
  }

  if (key.algorithm && usage === 'verify' && key.type === 'private') {
    throw new TypeError(`${_is_key_like.types.join(' or ')} instances for asymmetric algorithm verifying must be of type "public"`);
  }

  if (key.algorithm && usage === 'encrypt' && key.type === 'private') {
    throw new TypeError(`${_is_key_like.types.join(' or ')} instances for asymmetric algorithm encryption must be of type "public"`);
  }
};

const checkKeyType = (alg, key, usage) => {
  const symmetric = alg.startsWith('HS') || alg === 'dir' || alg.startsWith('PBES2') || /^A\d{3}(?:GCM)?KW$/.test(alg);

  if (symmetric) {
    symmetricTypeCheck(key);
  } else {
    asymmetricTypeCheck(key, usage);
  }
};

var _default = checkKeyType;
exports.default = _default;

},{"../runtime/is_key_like.js":109,"./invalid_key_input.js":87}],81:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = checkP2s;

var _errors = require("../util/errors.js");

function checkP2s(p2s) {
  if (!(p2s instanceof Uint8Array) || p2s.length < 8) {
    throw new _errors.JWEInvalid('PBES2 Salt Input must be 8 or more octets');
  }
}

},{"../util/errors.js":124}],82:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.checkEncCryptoKey = checkEncCryptoKey;
exports.checkSigCryptoKey = checkSigCryptoKey;

var _env = require("../runtime/env.js");

function unusable(name, prop = 'algorithm.name') {
  return new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
}

function isAlgorithm(algorithm, name) {
  return algorithm.name === name;
}

function getHashLength(hash) {
  return parseInt(hash.name.substr(4), 10);
}

function getNamedCurve(alg) {
  switch (alg) {
    case 'ES256':
      return 'P-256';

    case 'ES384':
      return 'P-384';

    case 'ES512':
      return 'P-521';

    default:
      throw new Error('unreachable');
  }
}

function checkUsage(key, usages) {
  if (usages.length && !usages.some(expected => key.usages.includes(expected))) {
    let msg = 'CryptoKey does not support this operation, its usages must include ';

    if (usages.length > 2) {
      const last = usages.pop();
      msg += `one of ${usages.join(', ')}, or ${last}.`;
    } else if (usages.length === 2) {
      msg += `one of ${usages[0]} or ${usages[1]}.`;
    } else {
      msg += `${usages[0]}.`;
    }

    throw new TypeError(msg);
  }
}

function checkSigCryptoKey(key, alg, ...usages) {
  switch (alg) {
    case 'HS256':
    case 'HS384':
    case 'HS512':
      {
        if (!isAlgorithm(key.algorithm, 'HMAC')) throw unusable('HMAC');
        const expected = parseInt(alg.substr(2), 10);
        const actual = getHashLength(key.algorithm.hash);
        if (actual !== expected) throw unusable(`SHA-${expected}`, 'algorithm.hash');
        break;
      }

    case 'RS256':
    case 'RS384':
    case 'RS512':
      {
        if (!isAlgorithm(key.algorithm, 'RSASSA-PKCS1-v1_5')) throw unusable('RSASSA-PKCS1-v1_5');
        const expected = parseInt(alg.substr(2), 10);
        const actual = getHashLength(key.algorithm.hash);
        if (actual !== expected) throw unusable(`SHA-${expected}`, 'algorithm.hash');
        break;
      }

    case 'PS256':
    case 'PS384':
    case 'PS512':
      {
        if (!isAlgorithm(key.algorithm, 'RSA-PSS')) throw unusable('RSA-PSS');
        const expected = parseInt(alg.substr(2), 10);
        const actual = getHashLength(key.algorithm.hash);
        if (actual !== expected) throw unusable(`SHA-${expected}`, 'algorithm.hash');
        break;
      }

    case (0, _env.isNodeJs)() && 'EdDSA':
      {
        if (key.algorithm.name !== 'NODE-ED25519' && key.algorithm.name !== 'NODE-ED448') throw unusable('NODE-ED25519 or NODE-ED448');
        break;
      }

    case (0, _env.isCloudflareWorkers)() && 'EdDSA':
      {
        if (!isAlgorithm(key.algorithm, 'NODE-ED25519')) throw unusable('NODE-ED25519');
        break;
      }

    case 'ES256':
    case 'ES384':
    case 'ES512':
      {
        if (!isAlgorithm(key.algorithm, 'ECDSA')) throw unusable('ECDSA');
        const expected = getNamedCurve(alg);
        const actual = key.algorithm.namedCurve;
        if (actual !== expected) throw unusable(expected, 'algorithm.namedCurve');
        break;
      }

    default:
      throw new TypeError('CryptoKey does not support this operation');
  }

  checkUsage(key, usages);
}

function checkEncCryptoKey(key, alg, ...usages) {
  switch (alg) {
    case 'A128GCM':
    case 'A192GCM':
    case 'A256GCM':
      {
        if (!isAlgorithm(key.algorithm, 'AES-GCM')) throw unusable('AES-GCM');
        const expected = parseInt(alg.substr(1, 3), 10);
        const actual = key.algorithm.length;
        if (actual !== expected) throw unusable(expected, 'algorithm.length');
        break;
      }

    case 'A128KW':
    case 'A192KW':
    case 'A256KW':
      {
        if (!isAlgorithm(key.algorithm, 'AES-KW')) throw unusable('AES-KW');
        const expected = parseInt(alg.substr(1, 3), 10);
        const actual = key.algorithm.length;
        if (actual !== expected) throw unusable(expected, 'algorithm.length');
        break;
      }

    case 'ECDH-ES':
      if (!isAlgorithm(key.algorithm, 'ECDH')) throw unusable('ECDH');
      break;

    case 'PBES2-HS256+A128KW':
    case 'PBES2-HS384+A192KW':
    case 'PBES2-HS512+A256KW':
      if (!isAlgorithm(key.algorithm, 'PBKDF2')) throw unusable('PBKDF2');
      break;

    case 'RSA-OAEP':
    case 'RSA-OAEP-256':
    case 'RSA-OAEP-384':
    case 'RSA-OAEP-512':
      {
        if (!isAlgorithm(key.algorithm, 'RSA-OAEP')) throw unusable('RSA-OAEP');
        const expected = parseInt(alg.substr(9), 10) || 1;
        const actual = getHashLength(key.algorithm.hash);
        if (actual !== expected) throw unusable(`SHA-${expected}`, 'algorithm.hash');
        break;
      }

    default:
      throw new TypeError('CryptoKey does not support this operation');
  }

  checkUsage(key, usages);
}

},{"../runtime/env.js":105}],83:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _aeskw = require("../runtime/aeskw.js");

var ECDH = _interopRequireWildcard(require("../runtime/ecdhes.js"));

var _pbes2kw = require("../runtime/pbes2kw.js");

var _rsaes = require("../runtime/rsaes.js");

var _base64url = require("../runtime/base64url.js");

var _errors = require("../util/errors.js");

var _cek = require("../lib/cek.js");

var _import = require("../key/import.js");

var _check_key_type = _interopRequireDefault(require("./check_key_type.js"));

var _is_object = _interopRequireDefault(require("./is_object.js"));

var _aesgcmkw = require("./aesgcmkw.js");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

async function decryptKeyManagement(alg, key, encryptedKey, joseHeader) {
  (0, _check_key_type.default)(alg, key, 'decrypt');

  switch (alg) {
    case 'dir':
      {
        if (encryptedKey !== undefined) throw new _errors.JWEInvalid('Encountered unexpected JWE Encrypted Key');
        return key;
      }

    case 'ECDH-ES':
      if (encryptedKey !== undefined) throw new _errors.JWEInvalid('Encountered unexpected JWE Encrypted Key');

    case 'ECDH-ES+A128KW':
    case 'ECDH-ES+A192KW':
    case 'ECDH-ES+A256KW':
      {
        if (!(0, _is_object.default)(joseHeader.epk)) throw new _errors.JWEInvalid(`JOSE Header "epk" (Ephemeral Public Key) missing or invalid`);
        if (!ECDH.ecdhAllowed(key)) throw new _errors.JOSENotSupported('ECDH-ES with the provided key is not allowed or not supported by your javascript runtime');
        const epk = await (0, _import.importJWK)(joseHeader.epk, alg);
        let partyUInfo;
        let partyVInfo;

        if (joseHeader.apu !== undefined) {
          if (typeof joseHeader.apu !== 'string') throw new _errors.JWEInvalid(`JOSE Header "apu" (Agreement PartyUInfo) invalid`);
          partyUInfo = (0, _base64url.decode)(joseHeader.apu);
        }

        if (joseHeader.apv !== undefined) {
          if (typeof joseHeader.apv !== 'string') throw new _errors.JWEInvalid(`JOSE Header "apv" (Agreement PartyVInfo) invalid`);
          partyVInfo = (0, _base64url.decode)(joseHeader.apv);
        }

        const sharedSecret = await ECDH.deriveKey(epk, key, alg === 'ECDH-ES' ? joseHeader.enc : alg, alg === 'ECDH-ES' ? (0, _cek.bitLength)(joseHeader.enc) : parseInt(alg.substr(-5, 3), 10), partyUInfo, partyVInfo);
        if (alg === 'ECDH-ES') return sharedSecret;
        if (encryptedKey === undefined) throw new _errors.JWEInvalid('JWE Encrypted Key missing');
        return (0, _aeskw.unwrap)(alg.substr(-6), sharedSecret, encryptedKey);
      }

    case 'RSA1_5':
    case 'RSA-OAEP':
    case 'RSA-OAEP-256':
    case 'RSA-OAEP-384':
    case 'RSA-OAEP-512':
      {
        if (encryptedKey === undefined) throw new _errors.JWEInvalid('JWE Encrypted Key missing');
        return (0, _rsaes.decrypt)(alg, key, encryptedKey);
      }

    case 'PBES2-HS256+A128KW':
    case 'PBES2-HS384+A192KW':
    case 'PBES2-HS512+A256KW':
      {
        if (encryptedKey === undefined) throw new _errors.JWEInvalid('JWE Encrypted Key missing');
        if (typeof joseHeader.p2c !== 'number') throw new _errors.JWEInvalid(`JOSE Header "p2c" (PBES2 Count) missing or invalid`);
        if (typeof joseHeader.p2s !== 'string') throw new _errors.JWEInvalid(`JOSE Header "p2s" (PBES2 Salt) missing or invalid`);
        return (0, _pbes2kw.decrypt)(alg, key, encryptedKey, joseHeader.p2c, (0, _base64url.decode)(joseHeader.p2s));
      }

    case 'A128KW':
    case 'A192KW':
    case 'A256KW':
      {
        if (encryptedKey === undefined) throw new _errors.JWEInvalid('JWE Encrypted Key missing');
        return (0, _aeskw.unwrap)(alg, key, encryptedKey);
      }

    case 'A128GCMKW':
    case 'A192GCMKW':
    case 'A256GCMKW':
      {
        if (encryptedKey === undefined) throw new _errors.JWEInvalid('JWE Encrypted Key missing');
        if (typeof joseHeader.iv !== 'string') throw new _errors.JWEInvalid(`JOSE Header "iv" (Initialization Vector) missing or invalid`);
        if (typeof joseHeader.tag !== 'string') throw new _errors.JWEInvalid(`JOSE Header "tag" (Authentication Tag) missing or invalid`);
        const iv = (0, _base64url.decode)(joseHeader.iv);
        const tag = (0, _base64url.decode)(joseHeader.tag);
        return (0, _aesgcmkw.unwrap)(alg, key, encryptedKey, iv, tag);
      }

    default:
      {
        throw new _errors.JOSENotSupported('Invalid or unsupported "alg" (JWE Algorithm) header value');
      }
  }
}

var _default = decryptKeyManagement;
exports.default = _default;

},{"../key/import.js":75,"../lib/cek.js":78,"../runtime/aeskw.js":95,"../runtime/base64url.js":97,"../runtime/ecdhes.js":103,"../runtime/pbes2kw.js":112,"../runtime/rsaes.js":114,"../util/errors.js":124,"./aesgcmkw.js":76,"./check_key_type.js":80,"./is_object.js":89}],84:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _aeskw = require("../runtime/aeskw.js");

var ECDH = _interopRequireWildcard(require("../runtime/ecdhes.js"));

var _pbes2kw = require("../runtime/pbes2kw.js");

var _rsaes = require("../runtime/rsaes.js");

var _base64url = require("../runtime/base64url.js");

var _cek = _interopRequireWildcard(require("../lib/cek.js"));

var _errors = require("../util/errors.js");

var _export = require("../key/export.js");

var _check_key_type = _interopRequireDefault(require("./check_key_type.js"));

var _aesgcmkw = require("./aesgcmkw.js");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

async function encryptKeyManagement(alg, enc, key, providedCek, providedParameters = {}) {
  let encryptedKey;
  let parameters;
  let cek;
  (0, _check_key_type.default)(alg, key, 'encrypt');

  switch (alg) {
    case 'dir':
      {
        cek = key;
        break;
      }

    case 'ECDH-ES':
    case 'ECDH-ES+A128KW':
    case 'ECDH-ES+A192KW':
    case 'ECDH-ES+A256KW':
      {
        if (!ECDH.ecdhAllowed(key)) {
          throw new _errors.JOSENotSupported('ECDH-ES with the provided key is not allowed or not supported by your javascript runtime');
        }

        const {
          apu,
          apv
        } = providedParameters;
        let {
          epk: ephemeralKey
        } = providedParameters;
        ephemeralKey || (ephemeralKey = await ECDH.generateEpk(key));
        const {
          x,
          y,
          crv,
          kty
        } = await (0, _export.exportJWK)(ephemeralKey);
        const sharedSecret = await ECDH.deriveKey(key, ephemeralKey, alg === 'ECDH-ES' ? enc : alg, alg === 'ECDH-ES' ? (0, _cek.bitLength)(enc) : parseInt(alg.substr(-5, 3), 10), apu, apv);
        parameters = {
          epk: {
            x,
            y,
            crv,
            kty
          }
        };
        if (apu) parameters.apu = (0, _base64url.encode)(apu);
        if (apv) parameters.apv = (0, _base64url.encode)(apv);

        if (alg === 'ECDH-ES') {
          cek = sharedSecret;
          break;
        }

        cek = providedCek || (0, _cek.default)(enc);
        const kwAlg = alg.substr(-6);
        encryptedKey = await (0, _aeskw.wrap)(kwAlg, sharedSecret, cek);
        break;
      }

    case 'RSA1_5':
    case 'RSA-OAEP':
    case 'RSA-OAEP-256':
    case 'RSA-OAEP-384':
    case 'RSA-OAEP-512':
      {
        cek = providedCek || (0, _cek.default)(enc);
        encryptedKey = await (0, _rsaes.encrypt)(alg, key, cek);
        break;
      }

    case 'PBES2-HS256+A128KW':
    case 'PBES2-HS384+A192KW':
    case 'PBES2-HS512+A256KW':
      {
        cek = providedCek || (0, _cek.default)(enc);
        const {
          p2c,
          p2s
        } = providedParameters;
        ({
          encryptedKey,
          ...parameters
        } = await (0, _pbes2kw.encrypt)(alg, key, cek, p2c, p2s));
        break;
      }

    case 'A128KW':
    case 'A192KW':
    case 'A256KW':
      {
        cek = providedCek || (0, _cek.default)(enc);
        encryptedKey = await (0, _aeskw.wrap)(alg, key, cek);
        break;
      }

    case 'A128GCMKW':
    case 'A192GCMKW':
    case 'A256GCMKW':
      {
        cek = providedCek || (0, _cek.default)(enc);
        const {
          iv
        } = providedParameters;
        ({
          encryptedKey,
          ...parameters
        } = await (0, _aesgcmkw.wrap)(alg, key, cek, iv));
        break;
      }

    default:
      {
        throw new _errors.JOSENotSupported('Invalid or unsupported "alg" (JWE Algorithm) header value');
      }
  }

  return {
    cek,
    encryptedKey,
    parameters
  };
}

var _default = encryptKeyManagement;
exports.default = _default;

},{"../key/export.js":72,"../lib/cek.js":78,"../runtime/aeskw.js":95,"../runtime/base64url.js":97,"../runtime/ecdhes.js":103,"../runtime/pbes2kw.js":112,"../runtime/rsaes.js":114,"../util/errors.js":124,"./aesgcmkw.js":76,"./check_key_type.js":80}],85:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _default = date => Math.floor(date.getTime() / 1000);

exports.default = _default;

},{}],86:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _default = (b64, descriptor) => {
  const newlined = (b64.match(/.{1,64}/g) || []).join('\n');
  return `-----BEGIN ${descriptor}-----\n${newlined}\n-----END ${descriptor}-----`;
};

exports.default = _default;

},{}],87:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _default = (actual, ...types) => {
  let msg = 'Key must be ';

  if (types.length > 2) {
    const last = types.pop();
    msg += `one of type ${types.join(', ')}, or ${last}.`;
  } else if (types.length === 2) {
    msg += `one of type ${types[0]} or ${types[1]}.`;
  } else {
    msg += `of type ${types[0]}.`;
  }

  if (actual == null) {
    msg += ` Received ${actual}`;
  } else if (typeof actual === 'function' && actual.name) {
    msg += ` Received function ${actual.name}`;
  } else if (typeof actual === 'object' && actual != null) {
    if (actual.constructor && actual.constructor.name) {
      msg += ` Received an instance of ${actual.constructor.name}`;
    }
  }

  return msg;
};

exports.default = _default;

},{}],88:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

const isDisjoint = (...headers) => {
  const sources = headers.filter(Boolean);

  if (sources.length === 0 || sources.length === 1) {
    return true;
  }

  let acc;

  for (const header of sources) {
    const parameters = Object.keys(header);

    if (!acc || acc.size === 0) {
      acc = new Set(parameters);
      continue;
    }

    for (const parameter of parameters) {
      if (acc.has(parameter)) {
        return false;
      }

      acc.add(parameter);
    }
  }

  return true;
};

var _default = isDisjoint;
exports.default = _default;

},{}],89:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = isObject;

function isObjectLike(value) {
  return typeof value === 'object' && value !== null;
}

function isObject(input) {
  if (!isObjectLike(input) || Object.prototype.toString.call(input) !== '[object Object]') {
    return false;
  }

  if (Object.getPrototypeOf(input) === null) {
    return true;
  }

  let proto = input;

  while (Object.getPrototypeOf(proto) !== null) {
    proto = Object.getPrototypeOf(proto);
  }

  return Object.getPrototypeOf(input) === proto;
}

},{}],90:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.bitLength = bitLength;
exports.default = void 0;

var _errors = require("../util/errors.js");

var _random = _interopRequireDefault(require("../runtime/random.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function bitLength(alg) {
  switch (alg) {
    case 'A128GCM':
    case 'A128GCMKW':
    case 'A192GCM':
    case 'A192GCMKW':
    case 'A256GCM':
    case 'A256GCMKW':
      return 96;

    case 'A128CBC-HS256':
    case 'A192CBC-HS384':
    case 'A256CBC-HS512':
      return 128;

    default:
      throw new _errors.JOSENotSupported(`Unsupported JWE Algorithm: ${alg}`);
  }
}

var _default = alg => (0, _random.default)(new Uint8Array(bitLength(alg) >> 3));

exports.default = _default;

},{"../runtime/random.js":113,"../util/errors.js":124}],91:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _errors = require("../util/errors.js");

var _buffer_utils = require("./buffer_utils.js");

var _epoch = _interopRequireDefault(require("./epoch.js"));

var _secs = _interopRequireDefault(require("./secs.js"));

var _is_object = _interopRequireDefault(require("./is_object.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const normalizeTyp = value => value.toLowerCase().replace(/^application\//, '');

const checkAudiencePresence = (audPayload, audOption) => {
  if (typeof audPayload === 'string') {
    return audOption.includes(audPayload);
  }

  if (Array.isArray(audPayload)) {
    return audOption.some(Set.prototype.has.bind(new Set(audPayload)));
  }

  return false;
};

var _default = (protectedHeader, encodedPayload, options = {}) => {
  const {
    typ
  } = options;

  if (typ && (typeof protectedHeader.typ !== 'string' || normalizeTyp(protectedHeader.typ) !== normalizeTyp(typ))) {
    throw new _errors.JWTClaimValidationFailed('unexpected "typ" JWT header value', 'typ', 'check_failed');
  }

  let payload;

  try {
    payload = JSON.parse(_buffer_utils.decoder.decode(encodedPayload));
  } catch (_a) {}

  if (!(0, _is_object.default)(payload)) {
    throw new _errors.JWTInvalid('JWT Claims Set must be a top-level JSON object');
  }

  const {
    issuer
  } = options;

  if (issuer && !(Array.isArray(issuer) ? issuer : [issuer]).includes(payload.iss)) {
    throw new _errors.JWTClaimValidationFailed('unexpected "iss" claim value', 'iss', 'check_failed');
  }

  const {
    subject
  } = options;

  if (subject && payload.sub !== subject) {
    throw new _errors.JWTClaimValidationFailed('unexpected "sub" claim value', 'sub', 'check_failed');
  }

  const {
    audience
  } = options;

  if (audience && !checkAudiencePresence(payload.aud, typeof audience === 'string' ? [audience] : audience)) {
    throw new _errors.JWTClaimValidationFailed('unexpected "aud" claim value', 'aud', 'check_failed');
  }

  let tolerance;

  switch (typeof options.clockTolerance) {
    case 'string':
      tolerance = (0, _secs.default)(options.clockTolerance);
      break;

    case 'number':
      tolerance = options.clockTolerance;
      break;

    case 'undefined':
      tolerance = 0;
      break;

    default:
      throw new TypeError('Invalid clockTolerance option type');
  }

  const {
    currentDate
  } = options;
  const now = (0, _epoch.default)(currentDate || new Date());

  if (payload.iat !== undefined || options.maxTokenAge) {
    if (typeof payload.iat !== 'number') {
      throw new _errors.JWTClaimValidationFailed('"iat" claim must be a number', 'iat', 'invalid');
    }

    if (payload.exp === undefined && payload.iat > now + tolerance) {
      throw new _errors.JWTClaimValidationFailed('"iat" claim timestamp check failed (it should be in the past)', 'iat', 'check_failed');
    }
  }

  if (payload.nbf !== undefined) {
    if (typeof payload.nbf !== 'number') {
      throw new _errors.JWTClaimValidationFailed('"nbf" claim must be a number', 'nbf', 'invalid');
    }

    if (payload.nbf > now + tolerance) {
      throw new _errors.JWTClaimValidationFailed('"nbf" claim timestamp check failed', 'nbf', 'check_failed');
    }
  }

  if (payload.exp !== undefined) {
    if (typeof payload.exp !== 'number') {
      throw new _errors.JWTClaimValidationFailed('"exp" claim must be a number', 'exp', 'invalid');
    }

    if (payload.exp <= now - tolerance) {
      throw new _errors.JWTExpired('"exp" claim timestamp check failed', 'exp', 'check_failed');
    }
  }

  if (options.maxTokenAge) {
    const age = now - payload.iat;
    const max = typeof options.maxTokenAge === 'number' ? options.maxTokenAge : (0, _secs.default)(options.maxTokenAge);

    if (age - tolerance > max) {
      throw new _errors.JWTExpired('"iat" claim timestamp check failed (too far in the past)', 'iat', 'check_failed');
    }

    if (age < 0 - tolerance) {
      throw new _errors.JWTClaimValidationFailed('"iat" claim timestamp check failed (it should be in the past)', 'iat', 'check_failed');
    }
  }

  return payload;
};

exports.default = _default;

},{"../util/errors.js":124,"./buffer_utils.js":77,"./epoch.js":85,"./is_object.js":89,"./secs.js":92}],92:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
const minute = 60;
const hour = minute * 60;
const day = hour * 24;
const week = day * 7;
const year = day * 365.25;
const REGEX = /^(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)$/i;

var _default = str => {
  const matched = REGEX.exec(str);

  if (!matched) {
    throw new TypeError('Invalid time period format');
  }

  const value = parseFloat(matched[1]);
  const unit = matched[2].toLowerCase();

  switch (unit) {
    case 'sec':
    case 'secs':
    case 'second':
    case 'seconds':
    case 's':
      return Math.round(value);

    case 'minute':
    case 'minutes':
    case 'min':
    case 'mins':
    case 'm':
      return Math.round(value * minute);

    case 'hour':
    case 'hours':
    case 'hr':
    case 'hrs':
    case 'h':
      return Math.round(value * hour);

    case 'day':
    case 'days':
    case 'd':
      return Math.round(value * day);

    case 'week':
    case 'weeks':
    case 'w':
      return Math.round(value * week);

    default:
      return Math.round(value * year);
  }
};

exports.default = _default;

},{}],93:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

const validateAlgorithms = (option, algorithms) => {
  if (algorithms !== undefined && (!Array.isArray(algorithms) || algorithms.some(s => typeof s !== 'string'))) {
    throw new TypeError(`"${option}" option must be an array of strings`);
  }

  if (!algorithms) {
    return undefined;
  }

  return new Set(algorithms);
};

var _default = validateAlgorithms;
exports.default = _default;

},{}],94:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _errors = require("../util/errors.js");

function validateCrit(Err, recognizedDefault, recognizedOption, protectedHeader, joseHeader) {
  if (joseHeader.crit !== undefined && protectedHeader.crit === undefined) {
    throw new Err('"crit" (Critical) Header Parameter MUST be integrity protected');
  }

  if (!protectedHeader || protectedHeader.crit === undefined) {
    return new Set();
  }

  if (!Array.isArray(protectedHeader.crit) || protectedHeader.crit.length === 0 || protectedHeader.crit.some(input => typeof input !== 'string' || input.length === 0)) {
    throw new Err('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
  }

  let recognized;

  if (recognizedOption !== undefined) {
    recognized = new Map([...Object.entries(recognizedOption), ...recognizedDefault.entries()]);
  } else {
    recognized = recognizedDefault;
  }

  for (const parameter of protectedHeader.crit) {
    if (!recognized.has(parameter)) {
      throw new _errors.JOSENotSupported(`Extension Header Parameter "${parameter}" is not recognized`);
    }

    if (joseHeader[parameter] === undefined) {
      throw new Err(`Extension Header Parameter "${parameter}" is missing`);
    } else if (recognized.get(parameter) && protectedHeader[parameter] === undefined) {
      throw new Err(`Extension Header Parameter "${parameter}" MUST be integrity protected`);
    }
  }

  return new Set(protectedHeader.crit);
}

var _default = validateCrit;
exports.default = _default;

},{"../util/errors.js":124}],95:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.wrap = exports.unwrap = void 0;

var _bogus = _interopRequireDefault(require("./bogus.js"));

var _webcrypto = _interopRequireWildcard(require("./webcrypto.js"));

var _crypto_key = require("../lib/crypto_key.js");

var _invalid_key_input = _interopRequireDefault(require("../lib/invalid_key_input.js"));

var _is_key_like = require("./is_key_like.js");

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function checkKeySize(key, alg) {
  if (key.algorithm.length !== parseInt(alg.substr(1, 3), 10)) {
    throw new TypeError(`Invalid key size for alg: ${alg}`);
  }
}

function getCryptoKey(key, alg, usage) {
  if ((0, _webcrypto.isCryptoKey)(key)) {
    (0, _crypto_key.checkEncCryptoKey)(key, alg, usage);
    return key;
  }

  if (key instanceof Uint8Array) {
    return _webcrypto.default.subtle.importKey('raw', key, 'AES-KW', true, [usage]);
  }

  throw new TypeError((0, _invalid_key_input.default)(key, ..._is_key_like.types, 'Uint8Array'));
}

const wrap = async (alg, key, cek) => {
  const cryptoKey = await getCryptoKey(key, alg, 'wrapKey');
  checkKeySize(cryptoKey, alg);
  const cryptoKeyCek = await _webcrypto.default.subtle.importKey('raw', cek, ..._bogus.default);
  return new Uint8Array(await _webcrypto.default.subtle.wrapKey('raw', cryptoKeyCek, cryptoKey, 'AES-KW'));
};

exports.wrap = wrap;

const unwrap = async (alg, key, encryptedKey) => {
  const cryptoKey = await getCryptoKey(key, alg, 'unwrapKey');
  checkKeySize(cryptoKey, alg);
  const cryptoKeyCek = await _webcrypto.default.subtle.unwrapKey('raw', encryptedKey, cryptoKey, 'AES-KW', ..._bogus.default);
  return new Uint8Array(await _webcrypto.default.subtle.exportKey('raw', cryptoKeyCek));
};

exports.unwrap = unwrap;

},{"../lib/crypto_key.js":82,"../lib/invalid_key_input.js":87,"./bogus.js":98,"./is_key_like.js":109,"./webcrypto.js":120}],96:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.toSPKI = exports.toPKCS8 = exports.fromSPKI = exports.fromPKCS8 = void 0;

var _env = require("./env.js");

var _webcrypto = _interopRequireWildcard(require("./webcrypto.js"));

var _invalid_key_input = _interopRequireDefault(require("../lib/invalid_key_input.js"));

var _base64url = require("./base64url.js");

var _format_pem = _interopRequireDefault(require("../lib/format_pem.js"));

var _errors = require("../util/errors.js");

var _is_key_like = require("./is_key_like.js");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

const genericExport = async (keyType, keyFormat, key) => {
  if (!(0, _webcrypto.isCryptoKey)(key)) {
    throw new TypeError((0, _invalid_key_input.default)(key, ..._is_key_like.types));
  }

  if (!key.extractable) {
    throw new TypeError('CryptoKey is not extractable');
  }

  if (key.type !== keyType) {
    throw new TypeError(`key is not a ${keyType} key`);
  }

  return (0, _format_pem.default)((0, _base64url.encodeBase64)(new Uint8Array(await _webcrypto.default.subtle.exportKey(keyFormat, key))), `${keyType.toUpperCase()} KEY`);
};

const toSPKI = key => {
  return genericExport('public', 'spki', key);
};

exports.toSPKI = toSPKI;

const toPKCS8 = key => {
  return genericExport('private', 'pkcs8', key);
};

exports.toPKCS8 = toPKCS8;

const getNamedCurve = keyData => {
  const keyDataStr = keyData.toString();

  switch (true) {
    case keyDataStr.includes(new Uint8Array([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]).toString()):
      return 'P-256';

    case keyDataStr.includes(new Uint8Array([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]).toString()):
      return 'P-384';

    case keyDataStr.includes(new Uint8Array([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]).toString()):
      return 'P-521';

    case ((0, _env.isCloudflareWorkers)() || (0, _env.isNodeJs)()) && keyDataStr.includes(new Uint8Array([0x06, 0x03, 0x2b, 0x65, 0x70]).toString()):
      return 'Ed25519';

    case (0, _env.isNodeJs)() && keyDataStr.includes(new Uint8Array([0x06, 0x03, 0x2b, 0x65, 0x71]).toString()):
      return 'Ed448';

    default:
      throw new _errors.JOSENotSupported('Invalid or unsupported EC Key Curve or OKP Key Sub Type');
  }
};

const genericImport = async (replace, keyFormat, pem, alg, options) => {
  var _a;

  let algorithm;
  let keyUsages;
  const keyData = new Uint8Array(atob(pem.replace(replace, '')).split('').map(c => c.charCodeAt(0)));
  const isPublic = keyFormat === 'spki';

  switch (alg) {
    case 'PS256':
    case 'PS384':
    case 'PS512':
      algorithm = {
        name: 'RSA-PSS',
        hash: `SHA-${alg.substr(-3)}`
      };
      keyUsages = isPublic ? ['verify'] : ['sign'];
      break;

    case 'RS256':
    case 'RS384':
    case 'RS512':
      algorithm = {
        name: 'RSASSA-PKCS1-v1_5',
        hash: `SHA-${alg.substr(-3)}`
      };
      keyUsages = isPublic ? ['verify'] : ['sign'];
      break;

    case 'RSA-OAEP':
    case 'RSA-OAEP-256':
    case 'RSA-OAEP-384':
    case 'RSA-OAEP-512':
      algorithm = {
        name: 'RSA-OAEP',
        hash: `SHA-${parseInt(alg.substr(-3), 10) || 1}`
      };
      keyUsages = isPublic ? ['encrypt', 'wrapKey'] : ['decrypt', 'unwrapKey'];
      break;

    case 'ES256':
      algorithm = {
        name: 'ECDSA',
        namedCurve: 'P-256'
      };
      keyUsages = isPublic ? ['verify'] : ['sign'];
      break;

    case 'ES384':
      algorithm = {
        name: 'ECDSA',
        namedCurve: 'P-384'
      };
      keyUsages = isPublic ? ['verify'] : ['sign'];
      break;

    case 'ES512':
      algorithm = {
        name: 'ECDSA',
        namedCurve: 'P-521'
      };
      keyUsages = isPublic ? ['verify'] : ['sign'];
      break;

    case 'ECDH-ES':
    case 'ECDH-ES+A128KW':
    case 'ECDH-ES+A192KW':
    case 'ECDH-ES+A256KW':
      algorithm = {
        name: 'ECDH',
        namedCurve: getNamedCurve(keyData)
      };
      keyUsages = isPublic ? [] : ['deriveBits'];
      break;

    case ((0, _env.isCloudflareWorkers)() || (0, _env.isNodeJs)()) && 'EdDSA':
      const namedCurve = getNamedCurve(keyData).toUpperCase();
      algorithm = {
        name: `NODE-${namedCurve}`,
        namedCurve: `NODE-${namedCurve}`
      };
      keyUsages = isPublic ? ['verify'] : ['sign'];
      break;

    default:
      throw new _errors.JOSENotSupported('Invalid or unsupported "alg" (Algorithm) value');
  }

  return _webcrypto.default.subtle.importKey(keyFormat, keyData, algorithm, (_a = options === null || options === void 0 ? void 0 : options.extractable) !== null && _a !== void 0 ? _a : false, keyUsages);
};

const fromPKCS8 = (pem, alg, options) => {
  return genericImport(/(?:-----(?:BEGIN|END) PRIVATE KEY-----|\s)/g, 'pkcs8', pem, alg, options);
};

exports.fromPKCS8 = fromPKCS8;

const fromSPKI = (pem, alg, options) => {
  return genericImport(/(?:-----(?:BEGIN|END) PUBLIC KEY-----|\s)/g, 'spki', pem, alg, options);
};

exports.fromSPKI = fromSPKI;

},{"../lib/format_pem.js":86,"../lib/invalid_key_input.js":87,"../util/errors.js":124,"./base64url.js":97,"./env.js":105,"./is_key_like.js":109,"./webcrypto.js":120}],97:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.encodeBase64 = exports.encode = exports.decodeBase64 = exports.decode = void 0;

var _buffer_utils = require("../lib/buffer_utils.js");

const encodeBase64 = input => {
  let unencoded = input;

  if (typeof unencoded === 'string') {
    unencoded = _buffer_utils.encoder.encode(unencoded);
  }

  const CHUNK_SIZE = 0x8000;
  const arr = [];

  for (let i = 0; i < unencoded.length; i += CHUNK_SIZE) {
    arr.push(String.fromCharCode.apply(null, unencoded.subarray(i, i + CHUNK_SIZE)));
  }

  return btoa(arr.join(''));
};

exports.encodeBase64 = encodeBase64;

const encode = input => {
  return encodeBase64(input).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
};

exports.encode = encode;

const decodeBase64 = encoded => {
  return new Uint8Array(atob(encoded).split('').map(c => c.charCodeAt(0)));
};

exports.decodeBase64 = decodeBase64;

const decode = input => {
  let encoded = input;

  if (encoded instanceof Uint8Array) {
    encoded = _buffer_utils.decoder.decode(encoded);
  }

  encoded = encoded.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');

  try {
    return decodeBase64(encoded);
  } catch (_a) {
    throw new TypeError('The input to be decoded is not correctly encoded.');
  }
};

exports.decode = decode;

},{"../lib/buffer_utils.js":77}],98:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
const bogusWebCrypto = [{
  hash: 'SHA-256',
  name: 'HMAC'
}, true, ['sign']];
var _default = bogusWebCrypto;
exports.default = _default;

},{}],99:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _errors = require("../util/errors.js");

const checkCekLength = (cek, expected) => {
  if (cek.length << 3 !== expected) {
    throw new _errors.JWEInvalid('Invalid Content Encryption Key length');
  }
};

var _default = checkCekLength;
exports.default = _default;

},{"../util/errors.js":124}],100:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _default = (alg, key) => {
  if (alg.startsWith('RS') || alg.startsWith('PS')) {
    const {
      modulusLength
    } = key.algorithm;

    if (typeof modulusLength !== 'number' || modulusLength < 2048) {
      throw new TypeError(`${alg} requires key modulusLength to be 2048 bits or larger`);
    }
  }
};

exports.default = _default;

},{}],101:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _buffer_utils = require("../lib/buffer_utils.js");

var _check_iv_length = _interopRequireDefault(require("../lib/check_iv_length.js"));

var _check_cek_length = _interopRequireDefault(require("./check_cek_length.js"));

var _timing_safe_equal = _interopRequireDefault(require("./timing_safe_equal.js"));

var _errors = require("../util/errors.js");

var _webcrypto = _interopRequireWildcard(require("./webcrypto.js"));

var _crypto_key = require("../lib/crypto_key.js");

var _invalid_key_input = _interopRequireDefault(require("../lib/invalid_key_input.js"));

var _is_key_like = require("./is_key_like.js");

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

async function cbcDecrypt(enc, cek, ciphertext, iv, tag, aad) {
  if (!(cek instanceof Uint8Array)) {
    throw new TypeError((0, _invalid_key_input.default)(cek, 'Uint8Array'));
  }

  const keySize = parseInt(enc.substr(1, 3), 10);
  const encKey = await _webcrypto.default.subtle.importKey('raw', cek.subarray(keySize >> 3), 'AES-CBC', false, ['decrypt']);
  const macKey = await _webcrypto.default.subtle.importKey('raw', cek.subarray(0, keySize >> 3), {
    hash: `SHA-${keySize << 1}`,
    name: 'HMAC'
  }, false, ['sign']);
  const macData = (0, _buffer_utils.concat)(aad, iv, ciphertext, (0, _buffer_utils.uint64be)(aad.length << 3));
  const expectedTag = new Uint8Array((await _webcrypto.default.subtle.sign('HMAC', macKey, macData)).slice(0, keySize >> 3));
  let macCheckPassed;

  try {
    macCheckPassed = (0, _timing_safe_equal.default)(tag, expectedTag);
  } catch (_a) {}

  if (!macCheckPassed) {
    throw new _errors.JWEDecryptionFailed();
  }

  let plaintext;

  try {
    plaintext = new Uint8Array(await _webcrypto.default.subtle.decrypt({
      iv,
      name: 'AES-CBC'
    }, encKey, ciphertext));
  } catch (_b) {}

  if (!plaintext) {
    throw new _errors.JWEDecryptionFailed();
  }

  return plaintext;
}

async function gcmDecrypt(enc, cek, ciphertext, iv, tag, aad) {
  let encKey;

  if (cek instanceof Uint8Array) {
    encKey = await _webcrypto.default.subtle.importKey('raw', cek, 'AES-GCM', false, ['decrypt']);
  } else {
    (0, _crypto_key.checkEncCryptoKey)(cek, enc, 'decrypt');
    encKey = cek;
  }

  try {
    return new Uint8Array(await _webcrypto.default.subtle.decrypt({
      additionalData: aad,
      iv,
      name: 'AES-GCM',
      tagLength: 128
    }, encKey, (0, _buffer_utils.concat)(ciphertext, tag)));
  } catch (_a) {
    throw new _errors.JWEDecryptionFailed();
  }
}

const decrypt = async (enc, cek, ciphertext, iv, tag, aad) => {
  if (!(0, _webcrypto.isCryptoKey)(cek) && !(cek instanceof Uint8Array)) {
    throw new TypeError((0, _invalid_key_input.default)(cek, ..._is_key_like.types, 'Uint8Array'));
  }

  (0, _check_iv_length.default)(enc, iv);

  switch (enc) {
    case 'A128CBC-HS256':
    case 'A192CBC-HS384':
    case 'A256CBC-HS512':
      if (cek instanceof Uint8Array) (0, _check_cek_length.default)(cek, parseInt(enc.substr(-3), 10));
      return cbcDecrypt(enc, cek, ciphertext, iv, tag, aad);

    case 'A128GCM':
    case 'A192GCM':
    case 'A256GCM':
      if (cek instanceof Uint8Array) (0, _check_cek_length.default)(cek, parseInt(enc.substr(1, 3), 10));
      return gcmDecrypt(enc, cek, ciphertext, iv, tag, aad);

    default:
      throw new _errors.JOSENotSupported('Unsupported JWE Content Encryption Algorithm');
  }
};

var _default = decrypt;
exports.default = _default;

},{"../lib/buffer_utils.js":77,"../lib/check_iv_length.js":79,"../lib/crypto_key.js":82,"../lib/invalid_key_input.js":87,"../util/errors.js":124,"./check_cek_length.js":99,"./is_key_like.js":109,"./timing_safe_equal.js":118,"./webcrypto.js":120}],102:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _webcrypto = _interopRequireDefault(require("./webcrypto.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const digest = async (algorithm, data) => {
  const subtleDigest = `SHA-${algorithm.substr(-3)}`;
  return new Uint8Array(await _webcrypto.default.subtle.digest(subtleDigest, data));
};

var _default = digest;
exports.default = _default;

},{"./webcrypto.js":120}],103:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.generateEpk = exports.ecdhAllowed = exports.deriveKey = void 0;

var _buffer_utils = require("../lib/buffer_utils.js");

var _webcrypto = _interopRequireWildcard(require("./webcrypto.js"));

var _crypto_key = require("../lib/crypto_key.js");

var _digest = _interopRequireDefault(require("./digest.js"));

var _invalid_key_input = _interopRequireDefault(require("../lib/invalid_key_input.js"));

var _is_key_like = require("./is_key_like.js");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

const deriveKey = async (publicKey, privateKey, algorithm, keyLength, apu = new Uint8Array(0), apv = new Uint8Array(0)) => {
  if (!(0, _webcrypto.isCryptoKey)(publicKey)) {
    throw new TypeError((0, _invalid_key_input.default)(publicKey, ..._is_key_like.types));
  }

  (0, _crypto_key.checkEncCryptoKey)(publicKey, 'ECDH-ES');

  if (!(0, _webcrypto.isCryptoKey)(privateKey)) {
    throw new TypeError((0, _invalid_key_input.default)(privateKey, ..._is_key_like.types));
  }

  (0, _crypto_key.checkEncCryptoKey)(privateKey, 'ECDH-ES', 'deriveBits', 'deriveKey');
  const value = (0, _buffer_utils.concat)((0, _buffer_utils.lengthAndInput)(_buffer_utils.encoder.encode(algorithm)), (0, _buffer_utils.lengthAndInput)(apu), (0, _buffer_utils.lengthAndInput)(apv), (0, _buffer_utils.uint32be)(keyLength));

  if (!privateKey.usages.includes('deriveBits')) {
    throw new TypeError('ECDH-ES private key "usages" must include "deriveBits"');
  }

  const sharedSecret = new Uint8Array(await _webcrypto.default.subtle.deriveBits({
    name: 'ECDH',
    public: publicKey
  }, privateKey, Math.ceil(parseInt(privateKey.algorithm.namedCurve.substr(-3), 10) / 8) << 3));
  return (0, _buffer_utils.concatKdf)(_digest.default, sharedSecret, keyLength, value);
};

exports.deriveKey = deriveKey;

const generateEpk = async key => {
  if (!(0, _webcrypto.isCryptoKey)(key)) {
    throw new TypeError((0, _invalid_key_input.default)(key, ..._is_key_like.types));
  }

  return (await _webcrypto.default.subtle.generateKey({
    name: 'ECDH',
    namedCurve: key.algorithm.namedCurve
  }, true, ['deriveBits'])).privateKey;
};

exports.generateEpk = generateEpk;

const ecdhAllowed = key => {
  if (!(0, _webcrypto.isCryptoKey)(key)) {
    throw new TypeError((0, _invalid_key_input.default)(key, ..._is_key_like.types));
  }

  return ['P-256', 'P-384', 'P-521'].includes(key.algorithm.namedCurve);
};

exports.ecdhAllowed = ecdhAllowed;

},{"../lib/buffer_utils.js":77,"../lib/crypto_key.js":82,"../lib/invalid_key_input.js":87,"./digest.js":102,"./is_key_like.js":109,"./webcrypto.js":120}],104:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _buffer_utils = require("../lib/buffer_utils.js");

var _check_iv_length = _interopRequireDefault(require("../lib/check_iv_length.js"));

var _check_cek_length = _interopRequireDefault(require("./check_cek_length.js"));

var _webcrypto = _interopRequireWildcard(require("./webcrypto.js"));

var _crypto_key = require("../lib/crypto_key.js");

var _invalid_key_input = _interopRequireDefault(require("../lib/invalid_key_input.js"));

var _errors = require("../util/errors.js");

var _is_key_like = require("./is_key_like.js");

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

async function cbcEncrypt(enc, plaintext, cek, iv, aad) {
  if (!(cek instanceof Uint8Array)) {
    throw new TypeError((0, _invalid_key_input.default)(cek, 'Uint8Array'));
  }

  const keySize = parseInt(enc.substr(1, 3), 10);
  const encKey = await _webcrypto.default.subtle.importKey('raw', cek.subarray(keySize >> 3), 'AES-CBC', false, ['encrypt']);
  const macKey = await _webcrypto.default.subtle.importKey('raw', cek.subarray(0, keySize >> 3), {
    hash: `SHA-${keySize << 1}`,
    name: 'HMAC'
  }, false, ['sign']);
  const ciphertext = new Uint8Array(await _webcrypto.default.subtle.encrypt({
    iv,
    name: 'AES-CBC'
  }, encKey, plaintext));
  const macData = (0, _buffer_utils.concat)(aad, iv, ciphertext, (0, _buffer_utils.uint64be)(aad.length << 3));
  const tag = new Uint8Array((await _webcrypto.default.subtle.sign('HMAC', macKey, macData)).slice(0, keySize >> 3));
  return {
    ciphertext,
    tag
  };
}

async function gcmEncrypt(enc, plaintext, cek, iv, aad) {
  let encKey;

  if (cek instanceof Uint8Array) {
    encKey = await _webcrypto.default.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  } else {
    (0, _crypto_key.checkEncCryptoKey)(cek, enc, 'encrypt');
    encKey = cek;
  }

  const encrypted = new Uint8Array(await _webcrypto.default.subtle.encrypt({
    additionalData: aad,
    iv,
    name: 'AES-GCM',
    tagLength: 128
  }, encKey, plaintext));
  const tag = encrypted.slice(-16);
  const ciphertext = encrypted.slice(0, -16);
  return {
    ciphertext,
    tag
  };
}

const encrypt = async (enc, plaintext, cek, iv, aad) => {
  if (!(0, _webcrypto.isCryptoKey)(cek) && !(cek instanceof Uint8Array)) {
    throw new TypeError((0, _invalid_key_input.default)(cek, ..._is_key_like.types, 'Uint8Array'));
  }

  (0, _check_iv_length.default)(enc, iv);

  switch (enc) {
    case 'A128CBC-HS256':
    case 'A192CBC-HS384':
    case 'A256CBC-HS512':
      if (cek instanceof Uint8Array) (0, _check_cek_length.default)(cek, parseInt(enc.substr(-3), 10));
      return cbcEncrypt(enc, plaintext, cek, iv, aad);

    case 'A128GCM':
    case 'A192GCM':
    case 'A256GCM':
      if (cek instanceof Uint8Array) (0, _check_cek_length.default)(cek, parseInt(enc.substr(1, 3), 10));
      return gcmEncrypt(enc, plaintext, cek, iv, aad);

    default:
      throw new _errors.JOSENotSupported('Unsupported JWE Content Encryption Algorithm');
  }
};

var _default = encrypt;
exports.default = _default;

},{"../lib/buffer_utils.js":77,"../lib/check_iv_length.js":79,"../lib/crypto_key.js":82,"../lib/invalid_key_input.js":87,"../util/errors.js":124,"./check_cek_length.js":99,"./is_key_like.js":109,"./webcrypto.js":120}],105:[function(require,module,exports){
(function (process){(function (){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.isCloudflareWorkers = isCloudflareWorkers;
exports.isNodeJs = isNodeJs;

function isCloudflareWorkers() {
  return typeof WebSocketPair === 'function';
}

function isNodeJs() {
  try {
    return process.versions.node !== undefined;
  } catch (_a) {
    return false;
  }
}

}).call(this)}).call(this,require('_process'))
},{"_process":135}],106:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _errors = require("../util/errors.js");

var _env = require("./env.js");

const fetchJwks = async (url, timeout) => {
  let controller;
  let id;
  let timedOut = false;

  if (typeof AbortController === 'function') {
    controller = new AbortController();
    id = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeout);
  }

  const response = await fetch(url.href, {
    signal: controller ? controller.signal : undefined,
    redirect: 'manual',
    method: 'GET',
    ...(!(0, _env.isCloudflareWorkers)() ? {
      referrerPolicy: 'no-referrer',
      credentials: 'omit',
      mode: 'cors'
    } : undefined)
  }).catch(err => {
    if (timedOut) throw new _errors.JWKSTimeout();
    throw err;
  });
  if (id !== undefined) clearTimeout(id);

  if (response.status !== 200) {
    throw new _errors.JOSEError('Expected 200 OK from the JSON Web Key Set HTTP response');
  }

  try {
    return await response.json();
  } catch (_a) {
    throw new _errors.JOSEError('Failed to parse the JSON Web Key Set HTTP response as JSON');
  }
};

var _default = fetchJwks;
exports.default = _default;

},{"../util/errors.js":124,"./env.js":105}],107:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.generateKeyPair = generateKeyPair;
exports.generateSecret = generateSecret;

var _env = require("./env.js");

var _webcrypto = _interopRequireDefault(require("./webcrypto.js"));

var _errors = require("../util/errors.js");

var _random = _interopRequireDefault(require("./random.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

async function generateSecret(alg, options) {
  var _a;

  let length;
  let algorithm;
  let keyUsages;

  switch (alg) {
    case 'HS256':
    case 'HS384':
    case 'HS512':
      length = parseInt(alg.substr(-3), 10);
      algorithm = {
        name: 'HMAC',
        hash: `SHA-${length}`,
        length
      };
      keyUsages = ['sign', 'verify'];
      break;

    case 'A128CBC-HS256':
    case 'A192CBC-HS384':
    case 'A256CBC-HS512':
      length = parseInt(alg.substr(-3), 10);
      return (0, _random.default)(new Uint8Array(length >> 3));

    case 'A128KW':
    case 'A192KW':
    case 'A256KW':
      length = parseInt(alg.substring(1, 4), 10);
      algorithm = {
        name: 'AES-KW',
        length
      };
      keyUsages = ['wrapKey', 'unwrapKey'];
      break;

    case 'A128GCMKW':
    case 'A192GCMKW':
    case 'A256GCMKW':
    case 'A128GCM':
    case 'A192GCM':
    case 'A256GCM':
      length = parseInt(alg.substring(1, 4), 10);
      algorithm = {
        name: 'AES-GCM',
        length
      };
      keyUsages = ['encrypt', 'decrypt'];
      break;

    default:
      throw new _errors.JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
  }

  return _webcrypto.default.subtle.generateKey(algorithm, (_a = options === null || options === void 0 ? void 0 : options.extractable) !== null && _a !== void 0 ? _a : false, keyUsages);
}

function getModulusLengthOption(options) {
  var _a;

  const modulusLength = (_a = options === null || options === void 0 ? void 0 : options.modulusLength) !== null && _a !== void 0 ? _a : 2048;

  if (typeof modulusLength !== 'number' || modulusLength < 2048) {
    throw new _errors.JOSENotSupported('Invalid or unsupported modulusLength option provided, 2048 bits or larger keys must be used');
  }

  return modulusLength;
}

async function generateKeyPair(alg, options) {
  var _a, _b;

  let algorithm;
  let keyUsages;

  switch (alg) {
    case 'PS256':
    case 'PS384':
    case 'PS512':
      algorithm = {
        name: 'RSA-PSS',
        hash: `SHA-${alg.substr(-3)}`,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        modulusLength: getModulusLengthOption(options)
      };
      keyUsages = ['sign', 'verify'];
      break;

    case 'RS256':
    case 'RS384':
    case 'RS512':
      algorithm = {
        name: 'RSASSA-PKCS1-v1_5',
        hash: `SHA-${alg.substr(-3)}`,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        modulusLength: getModulusLengthOption(options)
      };
      keyUsages = ['sign', 'verify'];
      break;

    case 'RSA-OAEP':
    case 'RSA-OAEP-256':
    case 'RSA-OAEP-384':
    case 'RSA-OAEP-512':
      algorithm = {
        name: 'RSA-OAEP',
        hash: `SHA-${parseInt(alg.substr(-3), 10) || 1}`,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        modulusLength: getModulusLengthOption(options)
      };
      keyUsages = ['decrypt', 'unwrapKey', 'encrypt', 'wrapKey'];
      break;

    case 'ES256':
      algorithm = {
        name: 'ECDSA',
        namedCurve: 'P-256'
      };
      keyUsages = ['sign', 'verify'];
      break;

    case 'ES384':
      algorithm = {
        name: 'ECDSA',
        namedCurve: 'P-384'
      };
      keyUsages = ['sign', 'verify'];
      break;

    case 'ES512':
      algorithm = {
        name: 'ECDSA',
        namedCurve: 'P-521'
      };
      keyUsages = ['sign', 'verify'];
      break;

    case ((0, _env.isCloudflareWorkers)() || (0, _env.isNodeJs)()) && 'EdDSA':
      switch (options === null || options === void 0 ? void 0 : options.crv) {
        case undefined:
        case 'Ed25519':
          algorithm = {
            name: 'NODE-ED25519',
            namedCurve: 'NODE-ED25519'
          };
          keyUsages = ['sign', 'verify'];
          break;

        case (0, _env.isNodeJs)() && 'Ed448':
          algorithm = {
            name: 'NODE-ED448',
            namedCurve: 'NODE-ED448'
          };
          keyUsages = ['sign', 'verify'];
          break;

        default:
          throw new _errors.JOSENotSupported('Invalid or unsupported crv option provided, supported values are Ed25519 and Ed448');
      }

      break;

    case 'ECDH-ES':
    case 'ECDH-ES+A128KW':
    case 'ECDH-ES+A192KW':
    case 'ECDH-ES+A256KW':
      algorithm = {
        name: 'ECDH',
        namedCurve: (_a = options === null || options === void 0 ? void 0 : options.crv) !== null && _a !== void 0 ? _a : 'P-256'
      };
      keyUsages = ['deriveKey', 'deriveBits'];
      break;

    default:
      throw new _errors.JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
  }

  return _webcrypto.default.subtle.generateKey(algorithm, (_b = options === null || options === void 0 ? void 0 : options.extractable) !== null && _b !== void 0 ? _b : false, keyUsages);
}

},{"../util/errors.js":124,"./env.js":105,"./random.js":113,"./webcrypto.js":120}],108:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = getCryptoKey;

var _webcrypto = _interopRequireWildcard(require("./webcrypto.js"));

var _crypto_key = require("../lib/crypto_key.js");

var _invalid_key_input = _interopRequireDefault(require("../lib/invalid_key_input.js"));

var _is_key_like = require("./is_key_like.js");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function getCryptoKey(alg, key, usage) {
  if ((0, _webcrypto.isCryptoKey)(key)) {
    (0, _crypto_key.checkSigCryptoKey)(key, alg, usage);
    return key;
  }

  if (key instanceof Uint8Array) {
    if (!alg.startsWith('HS')) {
      throw new TypeError((0, _invalid_key_input.default)(key, ..._is_key_like.types));
    }

    return _webcrypto.default.subtle.importKey('raw', key, {
      hash: `SHA-${alg.substr(-3)}`,
      name: 'HMAC'
    }, false, [usage]);
  }

  throw new TypeError((0, _invalid_key_input.default)(key, ..._is_key_like.types, 'Uint8Array'));
}

},{"../lib/crypto_key.js":82,"../lib/invalid_key_input.js":87,"./is_key_like.js":109,"./webcrypto.js":120}],109:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.types = exports.default = void 0;

var _webcrypto = require("./webcrypto.js");

var _default = key => {
  return (0, _webcrypto.isCryptoKey)(key);
};

exports.default = _default;
const types = ['CryptoKey'];
exports.types = types;

},{"./webcrypto.js":120}],110:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _env = require("./env.js");

var _webcrypto = _interopRequireDefault(require("./webcrypto.js"));

var _errors = require("../util/errors.js");

var _base64url = require("./base64url.js");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function subtleMapping(jwk) {
  let algorithm;
  let keyUsages;

  switch (jwk.kty) {
    case 'oct':
      {
        switch (jwk.alg) {
          case 'HS256':
          case 'HS384':
          case 'HS512':
            algorithm = {
              name: 'HMAC',
              hash: `SHA-${jwk.alg.substr(-3)}`
            };
            keyUsages = ['sign', 'verify'];
            break;

          case 'A128CBC-HS256':
          case 'A192CBC-HS384':
          case 'A256CBC-HS512':
            throw new _errors.JOSENotSupported(`${jwk.alg} keys cannot be imported as CryptoKey instances`);

          case 'A128GCM':
          case 'A192GCM':
          case 'A256GCM':
          case 'A128GCMKW':
          case 'A192GCMKW':
          case 'A256GCMKW':
            algorithm = {
              name: 'AES-GCM'
            };
            keyUsages = ['encrypt', 'decrypt'];
            break;

          case 'A128KW':
          case 'A192KW':
          case 'A256KW':
            algorithm = {
              name: 'AES-KW'
            };
            keyUsages = ['wrapKey', 'unwrapKey'];
            break;

          case 'PBES2-HS256+A128KW':
          case 'PBES2-HS384+A192KW':
          case 'PBES2-HS512+A256KW':
            algorithm = {
              name: 'PBKDF2'
            };
            keyUsages = ['deriveBits'];
            break;

          default:
            throw new _errors.JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
        }

        break;
      }

    case 'RSA':
      {
        switch (jwk.alg) {
          case 'PS256':
          case 'PS384':
          case 'PS512':
            algorithm = {
              name: 'RSA-PSS',
              hash: `SHA-${jwk.alg.substr(-3)}`
            };
            keyUsages = jwk.d ? ['sign'] : ['verify'];
            break;

          case 'RS256':
          case 'RS384':
          case 'RS512':
            algorithm = {
              name: 'RSASSA-PKCS1-v1_5',
              hash: `SHA-${jwk.alg.substr(-3)}`
            };
            keyUsages = jwk.d ? ['sign'] : ['verify'];
            break;

          case 'RSA-OAEP':
          case 'RSA-OAEP-256':
          case 'RSA-OAEP-384':
          case 'RSA-OAEP-512':
            algorithm = {
              name: 'RSA-OAEP',
              hash: `SHA-${parseInt(jwk.alg.substr(-3), 10) || 1}`
            };
            keyUsages = jwk.d ? ['decrypt', 'unwrapKey'] : ['encrypt', 'wrapKey'];
            break;

          default:
            throw new _errors.JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
        }

        break;
      }

    case 'EC':
      {
        switch (jwk.alg) {
          case 'ES256':
            algorithm = {
              name: 'ECDSA',
              namedCurve: 'P-256'
            };
            keyUsages = jwk.d ? ['sign'] : ['verify'];
            break;

          case 'ES384':
            algorithm = {
              name: 'ECDSA',
              namedCurve: 'P-384'
            };
            keyUsages = jwk.d ? ['sign'] : ['verify'];
            break;

          case 'ES512':
            algorithm = {
              name: 'ECDSA',
              namedCurve: 'P-521'
            };
            keyUsages = jwk.d ? ['sign'] : ['verify'];
            break;

          case 'ECDH-ES':
          case 'ECDH-ES+A128KW':
          case 'ECDH-ES+A192KW':
          case 'ECDH-ES+A256KW':
            algorithm = {
              name: 'ECDH',
              namedCurve: jwk.crv
            };
            keyUsages = jwk.d ? ['deriveBits'] : [];
            break;

          default:
            throw new _errors.JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
        }

        break;
      }

    case ((0, _env.isCloudflareWorkers)() || (0, _env.isNodeJs)()) && 'OKP':
      if (jwk.alg !== 'EdDSA') {
        throw new _errors.JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }

      switch (jwk.crv) {
        case 'Ed25519':
          algorithm = {
            name: 'NODE-ED25519',
            namedCurve: 'NODE-ED25519'
          };
          keyUsages = jwk.d ? ['sign'] : ['verify'];
          break;

        case (0, _env.isNodeJs)() && 'Ed448':
          algorithm = {
            name: 'NODE-ED448',
            namedCurve: 'NODE-ED448'
          };
          keyUsages = jwk.d ? ['sign'] : ['verify'];
          break;

        default:
          throw new _errors.JOSENotSupported('Invalid or unsupported JWK "crv" (Subtype of Key Pair) Parameter value');
      }

      break;

    default:
      throw new _errors.JOSENotSupported('Invalid or unsupported JWK "kty" (Key Type) Parameter value');
  }

  return {
    algorithm,
    keyUsages
  };
}

const parse = async jwk => {
  var _a, _b;

  const {
    algorithm,
    keyUsages
  } = subtleMapping(jwk);
  const rest = [algorithm, (_a = jwk.ext) !== null && _a !== void 0 ? _a : false, (_b = jwk.key_ops) !== null && _b !== void 0 ? _b : keyUsages];

  if (algorithm.name === 'PBKDF2') {
    return _webcrypto.default.subtle.importKey('raw', (0, _base64url.decode)(jwk.k), ...rest);
  }

  const keyData = { ...jwk
  };
  delete keyData.alg;
  return _webcrypto.default.subtle.importKey('jwk', keyData, ...rest);
};

var _default = parse;
exports.default = _default;

},{"../util/errors.js":124,"./base64url.js":97,"./env.js":105,"./webcrypto.js":120}],111:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _webcrypto = _interopRequireWildcard(require("./webcrypto.js"));

var _invalid_key_input = _interopRequireDefault(require("../lib/invalid_key_input.js"));

var _base64url = require("./base64url.js");

var _is_key_like = require("./is_key_like.js");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

const keyToJWK = async key => {
  if (key instanceof Uint8Array) {
    return {
      kty: 'oct',
      k: (0, _base64url.encode)(key)
    };
  }

  if (!(0, _webcrypto.isCryptoKey)(key)) {
    throw new TypeError((0, _invalid_key_input.default)(key, ..._is_key_like.types, 'Uint8Array'));
  }

  if (!key.extractable) {
    throw new TypeError('non-extractable CryptoKey cannot be exported as a JWK');
  }

  const {
    ext,
    key_ops,
    alg,
    use,
    ...jwk
  } = await _webcrypto.default.subtle.exportKey('jwk', key);
  return jwk;
};

var _default = keyToJWK;
exports.default = _default;

},{"../lib/invalid_key_input.js":87,"./base64url.js":97,"./is_key_like.js":109,"./webcrypto.js":120}],112:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.encrypt = exports.decrypt = void 0;

var _random = _interopRequireDefault(require("./random.js"));

var _buffer_utils = require("../lib/buffer_utils.js");

var _base64url = require("./base64url.js");

var _aeskw = require("./aeskw.js");

var _check_p2s = _interopRequireDefault(require("../lib/check_p2s.js"));

var _webcrypto = _interopRequireWildcard(require("./webcrypto.js"));

var _crypto_key = require("../lib/crypto_key.js");

var _invalid_key_input = _interopRequireDefault(require("../lib/invalid_key_input.js"));

var _is_key_like = require("./is_key_like.js");

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function getCryptoKey(key, alg) {
  if (key instanceof Uint8Array) {
    return _webcrypto.default.subtle.importKey('raw', key, 'PBKDF2', false, ['deriveBits']);
  }

  if ((0, _webcrypto.isCryptoKey)(key)) {
    (0, _crypto_key.checkEncCryptoKey)(key, alg, 'deriveBits', 'deriveKey');
    return key;
  }

  throw new TypeError((0, _invalid_key_input.default)(key, ..._is_key_like.types, 'Uint8Array'));
}

async function deriveKey(p2s, alg, p2c, key) {
  (0, _check_p2s.default)(p2s);
  const salt = (0, _buffer_utils.p2s)(alg, p2s);
  const keylen = parseInt(alg.substr(13, 3), 10);
  const subtleAlg = {
    hash: `SHA-${alg.substr(8, 3)}`,
    iterations: p2c,
    name: 'PBKDF2',
    salt
  };
  const wrapAlg = {
    length: keylen,
    name: 'AES-KW'
  };
  const cryptoKey = await getCryptoKey(key, alg);

  if (cryptoKey.usages.includes('deriveBits')) {
    return new Uint8Array(await _webcrypto.default.subtle.deriveBits(subtleAlg, cryptoKey, keylen));
  }

  if (cryptoKey.usages.includes('deriveKey')) {
    return _webcrypto.default.subtle.deriveKey(subtleAlg, cryptoKey, wrapAlg, false, ['wrapKey', 'unwrapKey']);
  }

  throw new TypeError('PBKDF2 key "usages" must include "deriveBits" or "deriveKey"');
}

const encrypt = async (alg, key, cek, p2c = Math.floor(Math.random() * 2049) + 2048, p2s = (0, _random.default)(new Uint8Array(16))) => {
  const derived = await deriveKey(p2s, alg, p2c, key);
  const encryptedKey = await (0, _aeskw.wrap)(alg.substr(-6), derived, cek);
  return {
    encryptedKey,
    p2c,
    p2s: (0, _base64url.encode)(p2s)
  };
};

exports.encrypt = encrypt;

const decrypt = async (alg, key, encryptedKey, p2c, p2s) => {
  const derived = await deriveKey(p2s, alg, p2c, key);
  return (0, _aeskw.unwrap)(alg.substr(-6), derived, encryptedKey);
};

exports.decrypt = decrypt;

},{"../lib/buffer_utils.js":77,"../lib/check_p2s.js":81,"../lib/crypto_key.js":82,"../lib/invalid_key_input.js":87,"./aeskw.js":95,"./base64url.js":97,"./is_key_like.js":109,"./random.js":113,"./webcrypto.js":120}],113:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _webcrypto = _interopRequireDefault(require("./webcrypto.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var _default = _webcrypto.default.getRandomValues.bind(_webcrypto.default);

exports.default = _default;

},{"./webcrypto.js":120}],114:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.encrypt = exports.decrypt = void 0;

var _subtle_rsaes = _interopRequireDefault(require("./subtle_rsaes.js"));

var _bogus = _interopRequireDefault(require("./bogus.js"));

var _webcrypto = _interopRequireWildcard(require("./webcrypto.js"));

var _crypto_key = require("../lib/crypto_key.js");

var _check_key_length = _interopRequireDefault(require("./check_key_length.js"));

var _invalid_key_input = _interopRequireDefault(require("../lib/invalid_key_input.js"));

var _is_key_like = require("./is_key_like.js");

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const encrypt = async (alg, key, cek) => {
  if (!(0, _webcrypto.isCryptoKey)(key)) {
    throw new TypeError((0, _invalid_key_input.default)(key, ..._is_key_like.types));
  }

  (0, _crypto_key.checkEncCryptoKey)(key, alg, 'encrypt', 'wrapKey');
  (0, _check_key_length.default)(alg, key);

  if (key.usages.includes('encrypt')) {
    return new Uint8Array(await _webcrypto.default.subtle.encrypt((0, _subtle_rsaes.default)(alg), key, cek));
  }

  if (key.usages.includes('wrapKey')) {
    const cryptoKeyCek = await _webcrypto.default.subtle.importKey('raw', cek, ..._bogus.default);
    return new Uint8Array(await _webcrypto.default.subtle.wrapKey('raw', cryptoKeyCek, key, (0, _subtle_rsaes.default)(alg)));
  }

  throw new TypeError('RSA-OAEP key "usages" must include "encrypt" or "wrapKey" for this operation');
};

exports.encrypt = encrypt;

const decrypt = async (alg, key, encryptedKey) => {
  if (!(0, _webcrypto.isCryptoKey)(key)) {
    throw new TypeError((0, _invalid_key_input.default)(key, ..._is_key_like.types));
  }

  (0, _crypto_key.checkEncCryptoKey)(key, alg, 'decrypt', 'unwrapKey');
  (0, _check_key_length.default)(alg, key);

  if (key.usages.includes('decrypt')) {
    return new Uint8Array(await _webcrypto.default.subtle.decrypt((0, _subtle_rsaes.default)(alg), key, encryptedKey));
  }

  if (key.usages.includes('unwrapKey')) {
    const cryptoKeyCek = await _webcrypto.default.subtle.unwrapKey('raw', encryptedKey, key, (0, _subtle_rsaes.default)(alg), ..._bogus.default);
    return new Uint8Array(await _webcrypto.default.subtle.exportKey('raw', cryptoKeyCek));
  }

  throw new TypeError('RSA-OAEP key "usages" must include "decrypt" or "unwrapKey" for this operation');
};

exports.decrypt = decrypt;

},{"../lib/crypto_key.js":82,"../lib/invalid_key_input.js":87,"./bogus.js":98,"./check_key_length.js":100,"./is_key_like.js":109,"./subtle_rsaes.js":117,"./webcrypto.js":120}],115:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _subtle_dsa = _interopRequireDefault(require("./subtle_dsa.js"));

var _webcrypto = _interopRequireDefault(require("./webcrypto.js"));

var _check_key_length = _interopRequireDefault(require("./check_key_length.js"));

var _get_sign_verify_key = _interopRequireDefault(require("./get_sign_verify_key.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const sign = async (alg, key, data) => {
  const cryptoKey = await (0, _get_sign_verify_key.default)(alg, key, 'sign');
  (0, _check_key_length.default)(alg, cryptoKey);
  const signature = await _webcrypto.default.subtle.sign((0, _subtle_dsa.default)(alg, cryptoKey.algorithm.namedCurve), cryptoKey, data);
  return new Uint8Array(signature);
};

var _default = sign;
exports.default = _default;

},{"./check_key_length.js":100,"./get_sign_verify_key.js":108,"./subtle_dsa.js":116,"./webcrypto.js":120}],116:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = subtleDsa;

var _env = require("./env.js");

var _errors = require("../util/errors.js");

function subtleDsa(alg, namedCurve) {
  const length = parseInt(alg.substr(-3), 10);

  switch (alg) {
    case 'HS256':
    case 'HS384':
    case 'HS512':
      return {
        hash: `SHA-${length}`,
        name: 'HMAC'
      };

    case 'PS256':
    case 'PS384':
    case 'PS512':
      return {
        hash: `SHA-${length}`,
        name: 'RSA-PSS',
        saltLength: length >> 3
      };

    case 'RS256':
    case 'RS384':
    case 'RS512':
      return {
        hash: `SHA-${length}`,
        name: 'RSASSA-PKCS1-v1_5'
      };

    case 'ES256':
    case 'ES384':
    case 'ES512':
      return {
        hash: `SHA-${length}`,
        name: 'ECDSA',
        namedCurve
      };

    case ((0, _env.isCloudflareWorkers)() || (0, _env.isNodeJs)()) && 'EdDSA':
      return {
        name: namedCurve,
        namedCurve
      };

    default:
      throw new _errors.JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
  }
}

},{"../util/errors.js":124,"./env.js":105}],117:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = subtleRsaEs;

var _errors = require("../util/errors.js");

function subtleRsaEs(alg) {
  switch (alg) {
    case 'RSA-OAEP':
    case 'RSA-OAEP-256':
    case 'RSA-OAEP-384':
    case 'RSA-OAEP-512':
      return 'RSA-OAEP';

    default:
      throw new _errors.JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
  }
}

},{"../util/errors.js":124}],118:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

const timingSafeEqual = (a, b) => {
  if (!(a instanceof Uint8Array)) {
    throw new TypeError('First argument must be a buffer');
  }

  if (!(b instanceof Uint8Array)) {
    throw new TypeError('Second argument must be a buffer');
  }

  if (a.length !== b.length) {
    throw new TypeError('Input buffers must have the same length');
  }

  const len = a.length;
  let out = 0;
  let i = -1;

  while (++i < len) {
    out |= a[i] ^ b[i];
  }

  return out === 0;
};

var _default = timingSafeEqual;
exports.default = _default;

},{}],119:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _subtle_dsa = _interopRequireDefault(require("./subtle_dsa.js"));

var _webcrypto = _interopRequireDefault(require("./webcrypto.js"));

var _check_key_length = _interopRequireDefault(require("./check_key_length.js"));

var _get_sign_verify_key = _interopRequireDefault(require("./get_sign_verify_key.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const verify = async (alg, key, signature, data) => {
  const cryptoKey = await (0, _get_sign_verify_key.default)(alg, key, 'verify');
  (0, _check_key_length.default)(alg, cryptoKey);
  const algorithm = (0, _subtle_dsa.default)(alg, cryptoKey.algorithm.namedCurve);

  try {
    return await _webcrypto.default.subtle.verify(algorithm, cryptoKey, signature, data);
  } catch (_a) {
    return false;
  }
};

var _default = verify;
exports.default = _default;

},{"./check_key_length.js":100,"./get_sign_verify_key.js":108,"./subtle_dsa.js":116,"./webcrypto.js":120}],120:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
exports.isCryptoKey = isCryptoKey;
var _default = crypto;
exports.default = _default;

function isCryptoKey(key) {
  try {
    return key != null && typeof key.extractable === 'boolean' && typeof key.algorithm.name === 'string' && typeof key.type === 'string';
  } catch (_a) {
    return false;
  }
}

},{}],121:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.inflate = exports.deflate = void 0;

var _errors = require("../util/errors.js");

const inflate = async () => {
  throw new _errors.JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported by your javascript runtime. You need to use the `inflateRaw` decrypt option to provide Inflate Raw implementation.');
};

exports.inflate = inflate;

const deflate = async () => {
  throw new _errors.JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported by your javascript runtime. You need to use the `deflateRaw` encrypt option to provide Deflate Raw implementation.');
};

exports.deflate = deflate;

},{"../util/errors.js":124}],122:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.encode = exports.decode = void 0;

var base64url = _interopRequireWildcard(require("../runtime/base64url.js"));

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

const encode = base64url.encode;
exports.encode = encode;
const decode = base64url.decode;
exports.decode = decode;

},{"../runtime/base64url.js":97}],123:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.decodeProtectedHeader = decodeProtectedHeader;

var _base64url = require("./base64url.js");

var _buffer_utils = require("../lib/buffer_utils.js");

var _is_object = _interopRequireDefault(require("../lib/is_object.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function decodeProtectedHeader(token) {
  let protectedB64u;

  if (typeof token === 'string') {
    const parts = token.split('.');

    if (parts.length === 3 || parts.length === 5) {
      ;
      [protectedB64u] = parts;
    }
  } else if (typeof token === 'object' && token) {
    if ('protected' in token) {
      protectedB64u = token.protected;
    } else {
      throw new TypeError('Token does not contain a Protected Header');
    }
  }

  try {
    if (typeof protectedB64u !== 'string' || !protectedB64u) {
      throw new Error();
    }

    const result = JSON.parse(_buffer_utils.decoder.decode((0, _base64url.decode)(protectedB64u)));

    if (!(0, _is_object.default)(result)) {
      throw new Error();
    }

    return result;
  } catch (_a) {
    throw new TypeError('Invalid Token or Protected Header formatting');
  }
}

},{"../lib/buffer_utils.js":77,"../lib/is_object.js":89,"./base64url.js":122}],124:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.JWTInvalid = exports.JWTExpired = exports.JWTClaimValidationFailed = exports.JWSSignatureVerificationFailed = exports.JWSInvalid = exports.JWKSTimeout = exports.JWKSNoMatchingKey = exports.JWKSMultipleMatchingKeys = exports.JWKSInvalid = exports.JWKInvalid = exports.JWEInvalid = exports.JWEDecryptionFailed = exports.JOSENotSupported = exports.JOSEError = exports.JOSEAlgNotAllowed = void 0;

class JOSEError extends Error {
  constructor(message) {
    var _a;

    super(message);
    this.code = 'ERR_JOSE_GENERIC';
    this.name = this.constructor.name;
    (_a = Error.captureStackTrace) === null || _a === void 0 ? void 0 : _a.call(Error, this, this.constructor);
  }

  static get code() {
    return 'ERR_JOSE_GENERIC';
  }

}

exports.JOSEError = JOSEError;

class JWTClaimValidationFailed extends JOSEError {
  constructor(message, claim = 'unspecified', reason = 'unspecified') {
    super(message);
    this.code = 'ERR_JWT_CLAIM_VALIDATION_FAILED';
    this.claim = claim;
    this.reason = reason;
  }

  static get code() {
    return 'ERR_JWT_CLAIM_VALIDATION_FAILED';
  }

}

exports.JWTClaimValidationFailed = JWTClaimValidationFailed;

class JWTExpired extends JOSEError {
  constructor(message, claim = 'unspecified', reason = 'unspecified') {
    super(message);
    this.code = 'ERR_JWT_EXPIRED';
    this.claim = claim;
    this.reason = reason;
  }

  static get code() {
    return 'ERR_JWT_EXPIRED';
  }

}

exports.JWTExpired = JWTExpired;

class JOSEAlgNotAllowed extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = 'ERR_JOSE_ALG_NOT_ALLOWED';
  }

  static get code() {
    return 'ERR_JOSE_ALG_NOT_ALLOWED';
  }

}

exports.JOSEAlgNotAllowed = JOSEAlgNotAllowed;

class JOSENotSupported extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = 'ERR_JOSE_NOT_SUPPORTED';
  }

  static get code() {
    return 'ERR_JOSE_NOT_SUPPORTED';
  }

}

exports.JOSENotSupported = JOSENotSupported;

class JWEDecryptionFailed extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = 'ERR_JWE_DECRYPTION_FAILED';
    this.message = 'decryption operation failed';
  }

  static get code() {
    return 'ERR_JWE_DECRYPTION_FAILED';
  }

}

exports.JWEDecryptionFailed = JWEDecryptionFailed;

class JWEInvalid extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = 'ERR_JWE_INVALID';
  }

  static get code() {
    return 'ERR_JWE_INVALID';
  }

}

exports.JWEInvalid = JWEInvalid;

class JWSInvalid extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = 'ERR_JWS_INVALID';
  }

  static get code() {
    return 'ERR_JWS_INVALID';
  }

}

exports.JWSInvalid = JWSInvalid;

class JWTInvalid extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = 'ERR_JWT_INVALID';
  }

  static get code() {
    return 'ERR_JWT_INVALID';
  }

}

exports.JWTInvalid = JWTInvalid;

class JWKInvalid extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = 'ERR_JWK_INVALID';
  }

  static get code() {
    return 'ERR_JWK_INVALID';
  }

}

exports.JWKInvalid = JWKInvalid;

class JWKSInvalid extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = 'ERR_JWKS_INVALID';
  }

  static get code() {
    return 'ERR_JWKS_INVALID';
  }

}

exports.JWKSInvalid = JWKSInvalid;

class JWKSNoMatchingKey extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = 'ERR_JWKS_NO_MATCHING_KEY';
    this.message = 'no applicable key found in the JSON Web Key Set';
  }

  static get code() {
    return 'ERR_JWKS_NO_MATCHING_KEY';
  }

}

exports.JWKSNoMatchingKey = JWKSNoMatchingKey;

class JWKSMultipleMatchingKeys extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = 'ERR_JWKS_MULTIPLE_MATCHING_KEYS';
    this.message = 'multiple matching keys found in the JSON Web Key Set';
  }

  static get code() {
    return 'ERR_JWKS_MULTIPLE_MATCHING_KEYS';
  }

}

exports.JWKSMultipleMatchingKeys = JWKSMultipleMatchingKeys;

class JWKSTimeout extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = 'ERR_JWKS_TIMEOUT';
    this.message = 'request timed out';
  }

  static get code() {
    return 'ERR_JWKS_TIMEOUT';
  }

}

exports.JWKSTimeout = JWKSTimeout;

class JWSSignatureVerificationFailed extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED';
    this.message = 'signature verification failed';
  }

  static get code() {
    return 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED';
  }

}

exports.JWSSignatureVerificationFailed = JWSSignatureVerificationFailed;

},{}],125:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
const RDF = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
      XSD = 'http://www.w3.org/2001/XMLSchema#',
      SWAP = 'http://www.w3.org/2000/10/swap/';
var _default = {
  xsd: {
    decimal: `${XSD}decimal`,
    boolean: `${XSD}boolean`,
    double: `${XSD}double`,
    integer: `${XSD}integer`,
    string: `${XSD}string`
  },
  rdf: {
    type: `${RDF}type`,
    nil: `${RDF}nil`,
    first: `${RDF}first`,
    rest: `${RDF}rest`,
    langString: `${RDF}langString`
  },
  owl: {
    sameAs: 'http://www.w3.org/2002/07/owl#sameAs'
  },
  r: {
    forSome: `${SWAP}reify#forSome`,
    forAll: `${SWAP}reify#forAll`
  },
  log: {
    implies: `${SWAP}log#implies`
  }
};
exports.default = _default;

},{}],126:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = exports.Variable = exports.Triple = exports.Term = exports.Quad = exports.NamedNode = exports.Literal = exports.DefaultGraph = exports.BlankNode = void 0;
exports.escapeQuotes = escapeQuotes;
exports.termFromId = termFromId;
exports.termToId = termToId;
exports.unescapeQuotes = unescapeQuotes;

var _IRIs = _interopRequireDefault(require("./IRIs"));

var _N3Util = require("./N3Util");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// N3.js implementations of the RDF/JS core data types
// See https://github.com/rdfjs/representation-task-force/blob/master/interface-spec.md
const {
  rdf,
  xsd
} = _IRIs.default; // eslint-disable-next-line prefer-const

let DEFAULTGRAPH;
let _blankNodeCounter = 0;
const escapedLiteral = /^"(.*".*)(?="[^"]*$)/;
const quadId = /^<<("(?:""|[^"])*"[^ ]*|[^ ]+) ("(?:""|[^"])*"[^ ]*|[^ ]+) ("(?:""|[^"])*"[^ ]*|[^ ]+) ?("(?:""|[^"])*"[^ ]*|[^ ]+)?>>$/; // ## DataFactory singleton

const DataFactory = {
  namedNode,
  blankNode,
  variable,
  literal,
  defaultGraph,
  quad,
  triple: quad
};
var _default = DataFactory; // ## Term constructor

exports.default = _default;

class Term {
  constructor(id) {
    this.id = id;
  } // ### The value of this term


  get value() {
    return this.id;
  } // ### Implement hashCode for Immutable.js, since we implement `equals`
  // https://immutable-js.com/docs/v4.0.0/ValueObject/#hashCode()


  get hashCode() {
    return 0;
  } // ### Returns whether this object represents the same term as the other


  equals(other) {
    // If both terms were created by this library,
    // equality can be computed through ids
    if (other instanceof Term) return this.id === other.id; // Otherwise, compare term type and value

    return !!other && this.termType === other.termType && this.value === other.value;
  } // ### Returns a plain object representation of this term


  toJSON() {
    return {
      termType: this.termType,
      value: this.value
    };
  }

} // ## NamedNode constructor


exports.Term = Term;

class NamedNode extends Term {
  // ### The term type of this term
  get termType() {
    return 'NamedNode';
  }

} // ## Literal constructor


exports.NamedNode = NamedNode;

class Literal extends Term {
  // ### The term type of this term
  get termType() {
    return 'Literal';
  } // ### The text value of this literal


  get value() {
    return this.id.substring(1, this.id.lastIndexOf('"'));
  } // ### The language of this literal


  get language() {
    // Find the last quotation mark (e.g., '"abc"@en-us')
    const id = this.id;
    let atPos = id.lastIndexOf('"') + 1; // If "@" it follows, return the remaining substring; empty otherwise

    return atPos < id.length && id[atPos++] === '@' ? id.substr(atPos).toLowerCase() : '';
  } // ### The datatype IRI of this literal


  get datatype() {
    return new NamedNode(this.datatypeString);
  } // ### The datatype string of this literal


  get datatypeString() {
    // Find the last quotation mark (e.g., '"abc"^^http://ex.org/types#t')
    const id = this.id,
          dtPos = id.lastIndexOf('"') + 1;
    const char = dtPos < id.length ? id[dtPos] : ''; // If "^" it follows, return the remaining substring

    return char === '^' ? id.substr(dtPos + 2) : // If "@" follows, return rdf:langString; xsd:string otherwise
    char !== '@' ? xsd.string : rdf.langString;
  } // ### Returns whether this object represents the same term as the other


  equals(other) {
    // If both literals were created by this library,
    // equality can be computed through ids
    if (other instanceof Literal) return this.id === other.id; // Otherwise, compare term type, value, language, and datatype

    return !!other && !!other.datatype && this.termType === other.termType && this.value === other.value && this.language === other.language && this.datatype.value === other.datatype.value;
  }

  toJSON() {
    return {
      termType: this.termType,
      value: this.value,
      language: this.language,
      datatype: {
        termType: 'NamedNode',
        value: this.datatypeString
      }
    };
  }

} // ## BlankNode constructor


exports.Literal = Literal;

class BlankNode extends Term {
  constructor(name) {
    super(`_:${name}`);
  } // ### The term type of this term


  get termType() {
    return 'BlankNode';
  } // ### The name of this blank node


  get value() {
    return this.id.substr(2);
  }

}

exports.BlankNode = BlankNode;

class Variable extends Term {
  constructor(name) {
    super(`?${name}`);
  } // ### The term type of this term


  get termType() {
    return 'Variable';
  } // ### The name of this variable


  get value() {
    return this.id.substr(1);
  }

} // ## DefaultGraph constructor


exports.Variable = Variable;

class DefaultGraph extends Term {
  constructor() {
    super('');
    return DEFAULTGRAPH || this;
  } // ### The term type of this term


  get termType() {
    return 'DefaultGraph';
  } // ### Returns whether this object represents the same term as the other


  equals(other) {
    // If both terms were created by this library,
    // equality can be computed through strict equality;
    // otherwise, compare term types.
    return this === other || !!other && this.termType === other.termType;
  }

} // ## DefaultGraph singleton


exports.DefaultGraph = DefaultGraph;
DEFAULTGRAPH = new DefaultGraph(); // ### Constructs a term from the given internal string ID

function termFromId(id, factory) {
  factory = factory || DataFactory; // Falsy value or empty string indicate the default graph

  if (!id) return factory.defaultGraph(); // Identify the term type based on the first character

  switch (id[0]) {
    case '?':
      return factory.variable(id.substr(1));

    case '_':
      return factory.blankNode(id.substr(2));

    case '"':
      // Shortcut for internal literals
      if (factory === DataFactory) return new Literal(id); // Literal without datatype or language

      if (id[id.length - 1] === '"') return factory.literal(id.substr(1, id.length - 2)); // Literal with datatype or language

      const endPos = id.lastIndexOf('"', id.length - 1);
      return factory.literal(id.substr(1, endPos - 1), id[endPos + 1] === '@' ? id.substr(endPos + 2) : factory.namedNode(id.substr(endPos + 3)));

    case '<':
      const components = quadId.exec(id);
      return factory.quad(termFromId(unescapeQuotes(components[1]), factory), termFromId(unescapeQuotes(components[2]), factory), termFromId(unescapeQuotes(components[3]), factory), components[4] && termFromId(unescapeQuotes(components[4]), factory));

    default:
      return factory.namedNode(id);
  }
} // ### Constructs an internal string ID from the given term or ID string


function termToId(term) {
  if (typeof term === 'string') return term;
  if (term instanceof Term && term.termType !== 'Quad') return term.id;
  if (!term) return DEFAULTGRAPH.id; // Term instantiated with another library

  switch (term.termType) {
    case 'NamedNode':
      return term.value;

    case 'BlankNode':
      return `_:${term.value}`;

    case 'Variable':
      return `?${term.value}`;

    case 'DefaultGraph':
      return '';

    case 'Literal':
      return `"${term.value}"${term.language ? `@${term.language}` : term.datatype && term.datatype.value !== xsd.string ? `^^${term.datatype.value}` : ''}`;

    case 'Quad':
      // To identify RDF* quad components, we escape quotes by doubling them.
      // This avoids the overhead of backslash parsing of Turtle-like syntaxes.
      return `<<${escapeQuotes(termToId(term.subject))} ${escapeQuotes(termToId(term.predicate))} ${escapeQuotes(termToId(term.object))}${(0, _N3Util.isDefaultGraph)(term.graph) ? '' : ` ${termToId(term.graph)}`}>>`;

    default:
      throw new Error(`Unexpected termType: ${term.termType}`);
  }
} // ## Quad constructor


class Quad extends Term {
  constructor(subject, predicate, object, graph) {
    super('');
    this._subject = subject;
    this._predicate = predicate;
    this._object = object;
    this._graph = graph || DEFAULTGRAPH;
  } // ### The term type of this term


  get termType() {
    return 'Quad';
  }

  get subject() {
    return this._subject;
  }

  get predicate() {
    return this._predicate;
  }

  get object() {
    return this._object;
  }

  get graph() {
    return this._graph;
  } // ### Returns a plain object representation of this quad


  toJSON() {
    return {
      termType: this.termType,
      subject: this._subject.toJSON(),
      predicate: this._predicate.toJSON(),
      object: this._object.toJSON(),
      graph: this._graph.toJSON()
    };
  } // ### Returns whether this object represents the same quad as the other


  equals(other) {
    return !!other && this._subject.equals(other.subject) && this._predicate.equals(other.predicate) && this._object.equals(other.object) && this._graph.equals(other.graph);
  }

}

exports.Triple = exports.Quad = Quad;

// ### Escapes the quotes within the given literal
function escapeQuotes(id) {
  return id.replace(escapedLiteral, (_, quoted) => `"${quoted.replace(/"/g, '""')}`);
} // ### Unescapes the quotes within the given literal


function unescapeQuotes(id) {
  return id.replace(escapedLiteral, (_, quoted) => `"${quoted.replace(/""/g, '"')}`);
} // ### Creates an IRI


function namedNode(iri) {
  return new NamedNode(iri);
} // ### Creates a blank node


function blankNode(name) {
  return new BlankNode(name || `n3-${_blankNodeCounter++}`);
} // ### Creates a literal


function literal(value, languageOrDataType) {
  // Create a language-tagged string
  if (typeof languageOrDataType === 'string') return new Literal(`"${value}"@${languageOrDataType.toLowerCase()}`); // Automatically determine datatype for booleans and numbers

  let datatype = languageOrDataType ? languageOrDataType.value : '';

  if (datatype === '') {
    // Convert a boolean
    if (typeof value === 'boolean') datatype = xsd.boolean; // Convert an integer or double
    else if (typeof value === 'number') {
      if (Number.isFinite(value)) datatype = Number.isInteger(value) ? xsd.integer : xsd.double;else {
        datatype = xsd.double;
        if (!Number.isNaN(value)) value = value > 0 ? 'INF' : '-INF';
      }
    }
  } // Create a datatyped literal


  return datatype === '' || datatype === xsd.string ? new Literal(`"${value}"`) : new Literal(`"${value}"^^${datatype}`);
} // ### Creates a variable


function variable(name) {
  return new Variable(name);
} // ### Returns the default graph


function defaultGraph() {
  return DEFAULTGRAPH;
} // ### Creates a quad


function quad(subject, predicate, object, graph) {
  return new Quad(subject, predicate, object, graph);
}

},{"./IRIs":125,"./N3Util":132}],127:[function(require,module,exports){
(function (Buffer){(function (){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _IRIs = _interopRequireDefault(require("./IRIs"));

var _queueMicrotask = _interopRequireDefault(require("queue-microtask"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// **N3Lexer** tokenizes N3 documents.
const {
  xsd
} = _IRIs.default; // Regular expression and replacement string to escape N3 strings

const escapeSequence = /\\u([a-fA-F0-9]{4})|\\U([a-fA-F0-9]{8})|\\([^])/g;
const escapeReplacements = {
  '\\': '\\',
  "'": "'",
  '"': '"',
  'n': '\n',
  'r': '\r',
  't': '\t',
  'f': '\f',
  'b': '\b',
  '_': '_',
  '~': '~',
  '.': '.',
  '-': '-',
  '!': '!',
  '$': '$',
  '&': '&',
  '(': '(',
  ')': ')',
  '*': '*',
  '+': '+',
  ',': ',',
  ';': ';',
  '=': '=',
  '/': '/',
  '?': '?',
  '#': '#',
  '@': '@',
  '%': '%'
};
const illegalIriChars = /[\x00-\x20<>\\"\{\}\|\^\`]/;
const lineModeRegExps = {
  _iri: true,
  _unescapedIri: true,
  _simpleQuotedString: true,
  _langcode: true,
  _blank: true,
  _newline: true,
  _comment: true,
  _whitespace: true,
  _endOfFile: true
};
const invalidRegExp = /$0^/; // ## Constructor

class N3Lexer {
  constructor(options) {
    // ## Regular expressions
    // It's slightly faster to have these as properties than as in-scope variables
    this._iri = /^<((?:[^ <>{}\\]|\\[uU])+)>[ \t]*/; // IRI with escape sequences; needs sanity check after unescaping

    this._unescapedIri = /^<([^\x00-\x20<>\\"\{\}\|\^\`]*)>[ \t]*/; // IRI without escape sequences; no unescaping

    this._simpleQuotedString = /^"([^"\\\r\n]*)"(?=[^"])/; // string without escape sequences

    this._simpleApostropheString = /^'([^'\\\r\n]*)'(?=[^'])/;
    this._langcode = /^@([a-z]+(?:-[a-z0-9]+)*)(?=[^a-z0-9\-])/i;
    this._prefix = /^((?:[A-Za-z\xc0-\xd6\xd8-\xf6\xf8-\u02ff\u0370-\u037d\u037f-\u1fff\u200c\u200d\u2070-\u218f\u2c00-\u2fef\u3001-\ud7ff\uf900-\ufdcf\ufdf0-\ufffd]|[\ud800-\udb7f][\udc00-\udfff])(?:\.?[\-0-9A-Z_a-z\xb7\xc0-\xd6\xd8-\xf6\xf8-\u037d\u037f-\u1fff\u200c\u200d\u203f\u2040\u2070-\u218f\u2c00-\u2fef\u3001-\ud7ff\uf900-\ufdcf\ufdf0-\ufffd]|[\ud800-\udb7f][\udc00-\udfff])*)?:(?=[#\s<])/;
    this._prefixed = /^((?:[A-Za-z\xc0-\xd6\xd8-\xf6\xf8-\u02ff\u0370-\u037d\u037f-\u1fff\u200c\u200d\u2070-\u218f\u2c00-\u2fef\u3001-\ud7ff\uf900-\ufdcf\ufdf0-\ufffd]|[\ud800-\udb7f][\udc00-\udfff])(?:\.?[\-0-9A-Z_a-z\xb7\xc0-\xd6\xd8-\xf6\xf8-\u037d\u037f-\u1fff\u200c\u200d\u203f\u2040\u2070-\u218f\u2c00-\u2fef\u3001-\ud7ff\uf900-\ufdcf\ufdf0-\ufffd]|[\ud800-\udb7f][\udc00-\udfff])*)?:((?:(?:[0-:A-Z_a-z\xc0-\xd6\xd8-\xf6\xf8-\u02ff\u0370-\u037d\u037f-\u1fff\u200c\u200d\u2070-\u218f\u2c00-\u2fef\u3001-\ud7ff\uf900-\ufdcf\ufdf0-\ufffd]|[\ud800-\udb7f][\udc00-\udfff]|%[0-9a-fA-F]{2}|\\[!#-\/;=?\-@_~])(?:(?:[\.\-0-:A-Z_a-z\xb7\xc0-\xd6\xd8-\xf6\xf8-\u037d\u037f-\u1fff\u200c\u200d\u203f\u2040\u2070-\u218f\u2c00-\u2fef\u3001-\ud7ff\uf900-\ufdcf\ufdf0-\ufffd]|[\ud800-\udb7f][\udc00-\udfff]|%[0-9a-fA-F]{2}|\\[!#-\/;=?\-@_~])*(?:[\-0-:A-Z_a-z\xb7\xc0-\xd6\xd8-\xf6\xf8-\u037d\u037f-\u1fff\u200c\u200d\u203f\u2040\u2070-\u218f\u2c00-\u2fef\u3001-\ud7ff\uf900-\ufdcf\ufdf0-\ufffd]|[\ud800-\udb7f][\udc00-\udfff]|%[0-9a-fA-F]{2}|\\[!#-\/;=?\-@_~]))?)?)(?:[ \t]+|(?=\.?[,;!\^\s#()\[\]\{\}"'<>]))/;
    this._variable = /^\?(?:(?:[A-Z_a-z\xc0-\xd6\xd8-\xf6\xf8-\u02ff\u0370-\u037d\u037f-\u1fff\u200c\u200d\u2070-\u218f\u2c00-\u2fef\u3001-\ud7ff\uf900-\ufdcf\ufdf0-\ufffd]|[\ud800-\udb7f][\udc00-\udfff])(?:[\-0-:A-Z_a-z\xb7\xc0-\xd6\xd8-\xf6\xf8-\u037d\u037f-\u1fff\u200c\u200d\u203f\u2040\u2070-\u218f\u2c00-\u2fef\u3001-\ud7ff\uf900-\ufdcf\ufdf0-\ufffd]|[\ud800-\udb7f][\udc00-\udfff])*)(?=[.,;!\^\s#()\[\]\{\}"'<>])/;
    this._blank = /^_:((?:[0-9A-Z_a-z\xc0-\xd6\xd8-\xf6\xf8-\u02ff\u0370-\u037d\u037f-\u1fff\u200c\u200d\u2070-\u218f\u2c00-\u2fef\u3001-\ud7ff\uf900-\ufdcf\ufdf0-\ufffd]|[\ud800-\udb7f][\udc00-\udfff])(?:\.?[\-0-9A-Z_a-z\xb7\xc0-\xd6\xd8-\xf6\xf8-\u037d\u037f-\u1fff\u200c\u200d\u203f\u2040\u2070-\u218f\u2c00-\u2fef\u3001-\ud7ff\uf900-\ufdcf\ufdf0-\ufffd]|[\ud800-\udb7f][\udc00-\udfff])*)(?:[ \t]+|(?=\.?[,;:\s#()\[\]\{\}"'<>]))/;
    this._number = /^[\-+]?(?:(\d+\.\d*|\.?\d+)[eE][\-+]?|\d*(\.)?)\d+(?=\.?[,;:\s#()\[\]\{\}"'<>])/;
    this._boolean = /^(?:true|false)(?=[.,;\s#()\[\]\{\}"'<>])/;
    this._keyword = /^@[a-z]+(?=[\s#<:])/i;
    this._sparqlKeyword = /^(?:PREFIX|BASE|GRAPH)(?=[\s#<])/i;
    this._shortPredicates = /^a(?=[\s#()\[\]\{\}"'<>])/;
    this._newline = /^[ \t]*(?:#[^\n\r]*)?(?:\r\n|\n|\r)[ \t]*/;
    this._comment = /#([^\n\r]*)/;
    this._whitespace = /^[ \t]+/;
    this._endOfFile = /^(?:#[^\n\r]*)?$/;
    options = options || {}; // In line mode (N-Triples or N-Quads), only simple features may be parsed

    if (this._lineMode = !!options.lineMode) {
      this._n3Mode = false; // Don't tokenize special literals

      for (const key in this) {
        if (!(key in lineModeRegExps) && this[key] instanceof RegExp) this[key] = invalidRegExp;
      }
    } // When not in line mode, enable N3 functionality by default
    else {
      this._n3Mode = options.n3 !== false;
    } // Don't output comment tokens by default


    this._comments = !!options.comments; // Cache the last tested closing position of long literals

    this._literalClosingPos = 0;
  } // ## Private methods
  // ### `_tokenizeToEnd` tokenizes as for as possible, emitting tokens through the callback


  _tokenizeToEnd(callback, inputFinished) {
    // Continue parsing as far as possible; the loop will return eventually
    let input = this._input;
    const outputComments = this._comments;

    while (true) {
      // Count and skip whitespace lines
      let whiteSpaceMatch, comment;

      while (whiteSpaceMatch = this._newline.exec(input)) {
        // Try to find a comment
        if (outputComments && (comment = this._comment.exec(whiteSpaceMatch[0]))) callback(null, {
          line: this._line,
          type: 'comment',
          value: comment[1],
          prefix: ''
        }); // Advance the input

        input = input.substr(whiteSpaceMatch[0].length, input.length);
        this._line++;
      } // Skip whitespace on current line


      if (!whiteSpaceMatch && (whiteSpaceMatch = this._whitespace.exec(input))) input = input.substr(whiteSpaceMatch[0].length, input.length); // Stop for now if we're at the end

      if (this._endOfFile.test(input)) {
        // If the input is finished, emit EOF
        if (inputFinished) {
          // Try to find a final comment
          if (outputComments && (comment = this._comment.exec(input))) callback(null, {
            line: this._line,
            type: 'comment',
            value: comment[1],
            prefix: ''
          });
          callback(input = null, {
            line: this._line,
            type: 'eof',
            value: '',
            prefix: ''
          });
        }

        return this._input = input;
      } // Look for specific token types based on the first character


      const line = this._line,
            firstChar = input[0];
      let type = '',
          value = '',
          prefix = '',
          match = null,
          matchLength = 0,
          inconclusive = false;

      switch (firstChar) {
        case '^':
          // We need at least 3 tokens lookahead to distinguish ^^<IRI> and ^^pre:fixed
          if (input.length < 3) break; // Try to match a type
          else if (input[1] === '^') {
            this._previousMarker = '^^'; // Move to type IRI or prefixed name

            input = input.substr(2);

            if (input[0] !== '<') {
              inconclusive = true;
              break;
            }
          } // If no type, it must be a path expression
          else {
            if (this._n3Mode) {
              matchLength = 1;
              type = '^';
            }

            break;
          }
        // Fall through in case the type is an IRI

        case '<':
          // Try to find a full IRI without escape sequences
          if (match = this._unescapedIri.exec(input)) type = 'IRI', value = match[1]; // Try to find a full IRI with escape sequences
          else if (match = this._iri.exec(input)) {
            value = this._unescape(match[1]);
            if (value === null || illegalIriChars.test(value)) return reportSyntaxError(this);
            type = 'IRI';
          } // Try to find a nested triple
          else if (input.length > 1 && input[1] === '<') type = '<<', matchLength = 2; // Try to find a backwards implication arrow
          else if (this._n3Mode && input.length > 1 && input[1] === '=') type = 'inverse', matchLength = 2, value = '>';
          break;

        case '>':
          if (input.length > 1 && input[1] === '>') type = '>>', matchLength = 2;
          break;

        case '_':
          // Try to find a blank node. Since it can contain (but not end with) a dot,
          // we always need a non-dot character before deciding it is a blank node.
          // Therefore, try inserting a space if we're at the end of the input.
          if ((match = this._blank.exec(input)) || inputFinished && (match = this._blank.exec(`${input} `))) type = 'blank', prefix = '_', value = match[1];
          break;

        case '"':
          // Try to find a literal without escape sequences
          if (match = this._simpleQuotedString.exec(input)) value = match[1]; // Try to find a literal wrapped in three pairs of quotes
          else {
            ({
              value,
              matchLength
            } = this._parseLiteral(input));
            if (value === null) return reportSyntaxError(this);
          }

          if (match !== null || matchLength !== 0) {
            type = 'literal';
            this._literalClosingPos = 0;
          }

          break;

        case "'":
          if (!this._lineMode) {
            // Try to find a literal without escape sequences
            if (match = this._simpleApostropheString.exec(input)) value = match[1]; // Try to find a literal wrapped in three pairs of quotes
            else {
              ({
                value,
                matchLength
              } = this._parseLiteral(input));
              if (value === null) return reportSyntaxError(this);
            }

            if (match !== null || matchLength !== 0) {
              type = 'literal';
              this._literalClosingPos = 0;
            }
          }

          break;

        case '?':
          // Try to find a variable
          if (this._n3Mode && (match = this._variable.exec(input))) type = 'var', value = match[0];
          break;

        case '@':
          // Try to find a language code
          if (this._previousMarker === 'literal' && (match = this._langcode.exec(input))) type = 'langcode', value = match[1]; // Try to find a keyword
          else if (match = this._keyword.exec(input)) type = match[0];
          break;

        case '.':
          // Try to find a dot as punctuation
          if (input.length === 1 ? inputFinished : input[1] < '0' || input[1] > '9') {
            type = '.';
            matchLength = 1;
            break;
          }

        // Fall through to numerical case (could be a decimal dot)

        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
        case '+':
        case '-':
          // Try to find a number. Since it can contain (but not end with) a dot,
          // we always need a non-dot character before deciding it is a number.
          // Therefore, try inserting a space if we're at the end of the input.
          if (match = this._number.exec(input) || inputFinished && (match = this._number.exec(`${input} `))) {
            type = 'literal', value = match[0];
            prefix = typeof match[1] === 'string' ? xsd.double : typeof match[2] === 'string' ? xsd.decimal : xsd.integer;
          }

          break;

        case 'B':
        case 'b':
        case 'p':
        case 'P':
        case 'G':
        case 'g':
          // Try to find a SPARQL-style keyword
          if (match = this._sparqlKeyword.exec(input)) type = match[0].toUpperCase();else inconclusive = true;
          break;

        case 'f':
        case 't':
          // Try to match a boolean
          if (match = this._boolean.exec(input)) type = 'literal', value = match[0], prefix = xsd.boolean;else inconclusive = true;
          break;

        case 'a':
          // Try to find an abbreviated predicate
          if (match = this._shortPredicates.exec(input)) type = 'abbreviation', value = 'a';else inconclusive = true;
          break;

        case '=':
          // Try to find an implication arrow or equals sign
          if (this._n3Mode && input.length > 1) {
            type = 'abbreviation';
            if (input[1] !== '>') matchLength = 1, value = '=';else matchLength = 2, value = '>';
          }

          break;

        case '!':
          if (!this._n3Mode) break;

        case ',':
        case ';':
        case '[':
        case ']':
        case '(':
        case ')':
        case '{':
        case '}':
          if (!this._lineMode) {
            matchLength = 1;
            type = firstChar;
          }

          break;

        default:
          inconclusive = true;
      } // Some first characters do not allow an immediate decision, so inspect more


      if (inconclusive) {
        // Try to find a prefix
        if ((this._previousMarker === '@prefix' || this._previousMarker === 'PREFIX') && (match = this._prefix.exec(input))) type = 'prefix', value = match[1] || ''; // Try to find a prefixed name. Since it can contain (but not end with) a dot,
        // we always need a non-dot character before deciding it is a prefixed name.
        // Therefore, try inserting a space if we're at the end of the input.
        else if ((match = this._prefixed.exec(input)) || inputFinished && (match = this._prefixed.exec(`${input} `))) type = 'prefixed', prefix = match[1] || '', value = this._unescape(match[2]);
      } // A type token is special: it can only be emitted after an IRI or prefixed name is read


      if (this._previousMarker === '^^') {
        switch (type) {
          case 'prefixed':
            type = 'type';
            break;

          case 'IRI':
            type = 'typeIRI';
            break;

          default:
            type = '';
        }
      } // What if nothing of the above was found?


      if (!type) {
        // We could be in streaming mode, and then we just wait for more input to arrive.
        // Otherwise, a syntax error has occurred in the input.
        // One exception: error on an unaccounted linebreak (= not inside a triple-quoted literal).
        if (inputFinished || !/^'''|^"""/.test(input) && /\n|\r/.test(input)) return reportSyntaxError(this);else return this._input = input;
      } // Emit the parsed token


      const token = {
        line: line,
        type: type,
        value: value,
        prefix: prefix
      };
      callback(null, token);
      this.previousToken = token;
      this._previousMarker = type; // Advance to next part to tokenize

      input = input.substr(matchLength || match[0].length, input.length);
    } // Signals the syntax error through the callback


    function reportSyntaxError(self) {
      callback(self._syntaxError(/^\S*/.exec(input)[0]));
    }
  } // ### `_unescape` replaces N3 escape codes by their corresponding characters


  _unescape(item) {
    let invalid = false;
    const replaced = item.replace(escapeSequence, (sequence, unicode4, unicode8, escapedChar) => {
      // 4-digit unicode character
      if (typeof unicode4 === 'string') return String.fromCharCode(Number.parseInt(unicode4, 16)); // 8-digit unicode character

      if (typeof unicode8 === 'string') {
        let charCode = Number.parseInt(unicode8, 16);
        return charCode <= 0xFFFF ? String.fromCharCode(Number.parseInt(unicode8, 16)) : String.fromCharCode(0xD800 + ((charCode -= 0x10000) >> 10), 0xDC00 + (charCode & 0x3FF));
      } // fixed escape sequence


      if (escapedChar in escapeReplacements) return escapeReplacements[escapedChar]; // invalid escape sequence

      invalid = true;
      return '';
    });
    return invalid ? null : replaced;
  } // ### `_parseLiteral` parses a literal into an unescaped value


  _parseLiteral(input) {
    // Ensure we have enough lookahead to identify triple-quoted strings
    if (input.length >= 3) {
      // Identify the opening quote(s)
      const opening = input.match(/^(?:"""|"|'''|'|)/)[0];
      const openingLength = opening.length; // Find the next candidate closing quotes

      let closingPos = Math.max(this._literalClosingPos, openingLength);

      while ((closingPos = input.indexOf(opening, closingPos)) > 0) {
        // Count backslashes right before the closing quotes
        let backslashCount = 0;

        while (input[closingPos - backslashCount - 1] === '\\') backslashCount++; // An even number of backslashes (in particular 0)
        // means these are actual, non-escaped closing quotes


        if (backslashCount % 2 === 0) {
          // Extract and unescape the value
          const raw = input.substring(openingLength, closingPos);
          const lines = raw.split(/\r\n|\r|\n/).length - 1;
          const matchLength = closingPos + openingLength; // Only triple-quoted strings can be multi-line

          if (openingLength === 1 && lines !== 0 || openingLength === 3 && this._lineMode) break;
          this._line += lines;
          return {
            value: this._unescape(raw),
            matchLength
          };
        }

        closingPos++;
      }

      this._literalClosingPos = input.length - openingLength + 1;
    }

    return {
      value: '',
      matchLength: 0
    };
  } // ### `_syntaxError` creates a syntax error for the given issue


  _syntaxError(issue) {
    this._input = null;
    const err = new Error(`Unexpected "${issue}" on line ${this._line}.`);
    err.context = {
      token: undefined,
      line: this._line,
      previousToken: this.previousToken
    };
    return err;
  } // ### Strips off any starting UTF BOM mark.


  _readStartingBom(input) {
    return input.startsWith('\ufeff') ? input.substr(1) : input;
  } // ## Public methods
  // ### `tokenize` starts the transformation of an N3 document into an array of tokens.
  // The input can be a string or a stream.


  tokenize(input, callback) {
    this._line = 1; // If the input is a string, continuously emit tokens through the callback until the end

    if (typeof input === 'string') {
      this._input = this._readStartingBom(input); // If a callback was passed, asynchronously call it

      if (typeof callback === 'function') (0, _queueMicrotask.default)(() => this._tokenizeToEnd(callback, true)); // If no callback was passed, tokenize synchronously and return
      else {
        const tokens = [];
        let error;

        this._tokenizeToEnd((e, t) => e ? error = e : tokens.push(t), true);

        if (error) throw error;
        return tokens;
      }
    } // Otherwise, the input must be a stream
    else {
      this._pendingBuffer = null;
      if (typeof input.setEncoding === 'function') input.setEncoding('utf8'); // Adds the data chunk to the buffer and parses as far as possible

      input.on('data', data => {
        if (this._input !== null && data.length !== 0) {
          // Prepend any previous pending writes
          if (this._pendingBuffer) {
            data = Buffer.concat([this._pendingBuffer, data]);
            this._pendingBuffer = null;
          } // Hold if the buffer ends in an incomplete unicode sequence


          if (data[data.length - 1] & 0x80) {
            this._pendingBuffer = data;
          } // Otherwise, tokenize as far as possible
          else {
            // Only read a BOM at the start
            if (typeof this._input === 'undefined') this._input = this._readStartingBom(typeof data === 'string' ? data : data.toString());else this._input += data;

            this._tokenizeToEnd(callback, false);
          }
        }
      }); // Parses until the end

      input.on('end', () => {
        if (typeof this._input === 'string') this._tokenizeToEnd(callback, true);
      });
      input.on('error', callback);
    }
  }

}

exports.default = N3Lexer;

}).call(this)}).call(this,require("buffer").Buffer)
},{"./IRIs":125,"buffer":44,"queue-microtask":136}],128:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _N3Lexer = _interopRequireDefault(require("./N3Lexer"));

var _N3DataFactory = _interopRequireDefault(require("./N3DataFactory"));

var _IRIs = _interopRequireDefault(require("./IRIs"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// **N3Parser** parses N3 documents.
let blankNodePrefix = 0; // ## Constructor

class N3Parser {
  constructor(options) {
    this._contextStack = [];
    this._graph = null; // Set the document IRI

    options = options || {};

    this._setBase(options.baseIRI);

    options.factory && initDataFactory(this, options.factory); // Set supported features depending on the format

    const format = typeof options.format === 'string' ? options.format.match(/\w*$/)[0].toLowerCase() : '',
          isTurtle = /turtle/.test(format),
          isTriG = /trig/.test(format),
          isNTriples = /triple/.test(format),
          isNQuads = /quad/.test(format),
          isN3 = this._n3Mode = /n3/.test(format),
          isLineMode = isNTriples || isNQuads;
    if (!(this._supportsNamedGraphs = !(isTurtle || isN3))) this._readPredicateOrNamedGraph = this._readPredicate; // Support triples in other graphs

    this._supportsQuads = !(isTurtle || isTriG || isNTriples || isN3); // Support nesting of triples

    this._supportsRDFStar = format === '' || /star|\*$/.test(format); // Disable relative IRIs in N-Triples or N-Quads mode

    if (isLineMode) this._resolveRelativeIRI = iri => {
      return null;
    };
    this._blankNodePrefix = typeof options.blankNodePrefix !== 'string' ? '' : options.blankNodePrefix.replace(/^(?!_:)/, '_:');
    this._lexer = options.lexer || new _N3Lexer.default({
      lineMode: isLineMode,
      n3: isN3
    }); // Disable explicit quantifiers by default

    this._explicitQuantifiers = !!options.explicitQuantifiers;
  } // ## Static class methods
  // ### `_resetBlankNodePrefix` restarts blank node prefix identification


  static _resetBlankNodePrefix() {
    blankNodePrefix = 0;
  } // ## Private methods
  // ### `_setBase` sets the base IRI to resolve relative IRIs


  _setBase(baseIRI) {
    if (!baseIRI) {
      this._base = '';
      this._basePath = '';
    } else {
      // Remove fragment if present
      const fragmentPos = baseIRI.indexOf('#');
      if (fragmentPos >= 0) baseIRI = baseIRI.substr(0, fragmentPos); // Set base IRI and its components

      this._base = baseIRI;
      this._basePath = baseIRI.indexOf('/') < 0 ? baseIRI : baseIRI.replace(/[^\/?]*(?:\?.*)?$/, '');
      baseIRI = baseIRI.match(/^(?:([a-z][a-z0-9+.-]*:))?(?:\/\/[^\/]*)?/i);
      this._baseRoot = baseIRI[0];
      this._baseScheme = baseIRI[1];
    }
  } // ### `_saveContext` stores the current parsing context
  // when entering a new scope (list, blank node, formula)


  _saveContext(type, graph, subject, predicate, object) {
    const n3Mode = this._n3Mode;

    this._contextStack.push({
      subject: subject,
      predicate: predicate,
      object: object,
      graph: graph,
      type: type,
      inverse: n3Mode ? this._inversePredicate : false,
      blankPrefix: n3Mode ? this._prefixes._ : '',
      quantified: n3Mode ? this._quantified : null
    }); // The settings below only apply to N3 streams


    if (n3Mode) {
      // Every new scope resets the predicate direction
      this._inversePredicate = false; // In N3, blank nodes are scoped to a formula
      // (using a dot as separator, as a blank node label cannot start with it)

      this._prefixes._ = this._graph ? `${this._graph.id.substr(2)}.` : '.'; // Quantifiers are scoped to a formula

      this._quantified = Object.create(this._quantified);
    }
  } // ### `_restoreContext` restores the parent context
  // when leaving a scope (list, blank node, formula)


  _restoreContext() {
    const context = this._contextStack.pop(),
          n3Mode = this._n3Mode;

    this._subject = context.subject;
    this._predicate = context.predicate;
    this._object = context.object;
    this._graph = context.graph; // The settings below only apply to N3 streams

    if (n3Mode) {
      this._inversePredicate = context.inverse;
      this._prefixes._ = context.blankPrefix;
      this._quantified = context.quantified;
    }
  } // ### `_readInTopContext` reads a token when in the top context


  _readInTopContext(token) {
    switch (token.type) {
      // If an EOF token arrives in the top context, signal that we're done
      case 'eof':
        if (this._graph !== null) return this._error('Unclosed graph', token);
        delete this._prefixes._;
        return this._callback(null, null, this._prefixes);
      // It could be a prefix declaration

      case 'PREFIX':
        this._sparqlStyle = true;

      case '@prefix':
        return this._readPrefix;
      // It could be a base declaration

      case 'BASE':
        this._sparqlStyle = true;

      case '@base':
        return this._readBaseIRI;
      // It could be a graph

      case '{':
        if (this._supportsNamedGraphs) {
          this._graph = '';
          this._subject = null;
          return this._readSubject;
        }

      case 'GRAPH':
        if (this._supportsNamedGraphs) return this._readNamedGraphLabel;
      // Otherwise, the next token must be a subject

      default:
        return this._readSubject(token);
    }
  } // ### `_readEntity` reads an IRI, prefixed name, blank node, or variable


  _readEntity(token, quantifier) {
    let value;

    switch (token.type) {
      // Read a relative or absolute IRI
      case 'IRI':
      case 'typeIRI':
        const iri = this._resolveIRI(token.value);

        if (iri === null) return this._error('Invalid IRI', token);
        value = this._namedNode(iri);
        break;
      // Read a prefixed name

      case 'type':
      case 'prefixed':
        const prefix = this._prefixes[token.prefix];
        if (prefix === undefined) return this._error(`Undefined prefix "${token.prefix}:"`, token);
        value = this._namedNode(prefix + token.value);
        break;
      // Read a blank node

      case 'blank':
        value = this._blankNode(this._prefixes[token.prefix] + token.value);
        break;
      // Read a variable

      case 'var':
        value = this._variable(token.value.substr(1));
        break;
      // Everything else is not an entity

      default:
        return this._error(`Expected entity but got ${token.type}`, token);
    } // In N3 mode, replace the entity if it is quantified


    if (!quantifier && this._n3Mode && value.id in this._quantified) value = this._quantified[value.id];
    return value;
  } // ### `_readSubject` reads a quad's subject


  _readSubject(token) {
    this._predicate = null;

    switch (token.type) {
      case '[':
        // Start a new quad with a new blank node as subject
        this._saveContext('blank', this._graph, this._subject = this._blankNode(), null, null);

        return this._readBlankNodeHead;

      case '(':
        // Start a new list
        this._saveContext('list', this._graph, this.RDF_NIL, null, null);

        this._subject = null;
        return this._readListItem;

      case '{':
        // Start a new formula
        if (!this._n3Mode) return this._error('Unexpected graph', token);

        this._saveContext('formula', this._graph, this._graph = this._blankNode(), null, null);

        return this._readSubject;

      case '}':
        // No subject; the graph in which we are reading is closed instead
        return this._readPunctuation(token);

      case '@forSome':
        if (!this._n3Mode) return this._error('Unexpected "@forSome"', token);
        this._subject = null;
        this._predicate = this.N3_FORSOME;
        this._quantifier = this._blankNode;
        return this._readQuantifierList;

      case '@forAll':
        if (!this._n3Mode) return this._error('Unexpected "@forAll"', token);
        this._subject = null;
        this._predicate = this.N3_FORALL;
        this._quantifier = this._variable;
        return this._readQuantifierList;

      case 'literal':
        if (!this._n3Mode) return this._error('Unexpected literal', token);

        if (token.prefix.length === 0) {
          this._literalValue = token.value;
          return this._completeSubjectLiteral;
        } else this._subject = this._literal(token.value, this._namedNode(token.prefix));

        break;

      case '<<':
        if (!this._supportsRDFStar) return this._error('Unexpected RDF* syntax', token);

        this._saveContext('<<', this._graph, null, null, null);

        this._graph = null;
        return this._readSubject;

      default:
        // Read the subject entity
        if ((this._subject = this._readEntity(token)) === undefined) return; // In N3 mode, the subject might be a path

        if (this._n3Mode) return this._getPathReader(this._readPredicateOrNamedGraph);
    } // The next token must be a predicate,
    // or, if the subject was actually a graph IRI, a named graph


    return this._readPredicateOrNamedGraph;
  } // ### `_readPredicate` reads a quad's predicate


  _readPredicate(token) {
    const type = token.type;

    switch (type) {
      case 'inverse':
        this._inversePredicate = true;

      case 'abbreviation':
        this._predicate = this.ABBREVIATIONS[token.value];
        break;

      case '.':
      case ']':
      case '}':
        // Expected predicate didn't come, must have been trailing semicolon
        if (this._predicate === null) return this._error(`Unexpected ${type}`, token);
        this._subject = null;
        return type === ']' ? this._readBlankNodeTail(token) : this._readPunctuation(token);

      case ';':
        // Additional semicolons can be safely ignored
        return this._predicate !== null ? this._readPredicate : this._error('Expected predicate but got ;', token);

      case '[':
        if (this._n3Mode) {
          // Start a new quad with a new blank node as subject
          this._saveContext('blank', this._graph, this._subject, this._subject = this._blankNode(), null);

          return this._readBlankNodeHead;
        }

      case 'blank':
        if (!this._n3Mode) return this._error('Disallowed blank node as predicate', token);

      default:
        if ((this._predicate = this._readEntity(token)) === undefined) return;
    } // The next token must be an object


    return this._readObject;
  } // ### `_readObject` reads a quad's object


  _readObject(token) {
    switch (token.type) {
      case 'literal':
        // Regular literal, can still get a datatype or language
        if (token.prefix.length === 0) {
          this._literalValue = token.value;
          return this._readDataTypeOrLang;
        } // Pre-datatyped string literal (prefix stores the datatype)
        else this._object = this._literal(token.value, this._namedNode(token.prefix));

        break;

      case '[':
        // Start a new quad with a new blank node as subject
        this._saveContext('blank', this._graph, this._subject, this._predicate, this._subject = this._blankNode());

        return this._readBlankNodeHead;

      case '(':
        // Start a new list
        this._saveContext('list', this._graph, this._subject, this._predicate, this.RDF_NIL);

        this._subject = null;
        return this._readListItem;

      case '{':
        // Start a new formula
        if (!this._n3Mode) return this._error('Unexpected graph', token);

        this._saveContext('formula', this._graph, this._subject, this._predicate, this._graph = this._blankNode());

        return this._readSubject;

      case '<<':
        if (!this._supportsRDFStar) return this._error('Unexpected RDF* syntax', token);

        this._saveContext('<<', this._graph, this._subject, this._predicate, null);

        this._graph = null;
        return this._readSubject;

      default:
        // Read the object entity
        if ((this._object = this._readEntity(token)) === undefined) return; // In N3 mode, the object might be a path

        if (this._n3Mode) return this._getPathReader(this._getContextEndReader());
    }

    return this._getContextEndReader();
  } // ### `_readPredicateOrNamedGraph` reads a quad's predicate, or a named graph


  _readPredicateOrNamedGraph(token) {
    return token.type === '{' ? this._readGraph(token) : this._readPredicate(token);
  } // ### `_readGraph` reads a graph


  _readGraph(token) {
    if (token.type !== '{') return this._error(`Expected graph but got ${token.type}`, token); // The "subject" we read is actually the GRAPH's label

    this._graph = this._subject, this._subject = null;
    return this._readSubject;
  } // ### `_readBlankNodeHead` reads the head of a blank node


  _readBlankNodeHead(token) {
    if (token.type === ']') {
      this._subject = null;
      return this._readBlankNodeTail(token);
    } else {
      this._predicate = null;
      return this._readPredicate(token);
    }
  } // ### `_readBlankNodeTail` reads the end of a blank node


  _readBlankNodeTail(token) {
    if (token.type !== ']') return this._readBlankNodePunctuation(token); // Store blank node quad

    if (this._subject !== null) this._emit(this._subject, this._predicate, this._object, this._graph); // Restore the parent context containing this blank node

    const empty = this._predicate === null;

    this._restoreContext(); // If the blank node was the object, restore previous context and read punctuation


    if (this._object !== null) return this._getContextEndReader(); // If the blank node was the predicate, continue reading the object
    else if (this._predicate !== null) return this._readObject; // If the blank node was the subject, continue reading the predicate
    else // If the blank node was empty, it could be a named graph label
      return empty ? this._readPredicateOrNamedGraph : this._readPredicateAfterBlank;
  } // ### `_readPredicateAfterBlank` reads a predicate after an anonymous blank node


  _readPredicateAfterBlank(token) {
    switch (token.type) {
      case '.':
      case '}':
        // No predicate is coming if the triple is terminated here
        this._subject = null;
        return this._readPunctuation(token);

      default:
        return this._readPredicate(token);
    }
  } // ### `_readListItem` reads items from a list


  _readListItem(token) {
    let item = null,
        // The item of the list
    list = null,
        // The list itself
    next = this._readListItem; // The next function to execute

    const previousList = this._subject,
          // The previous list that contains this list
    stack = this._contextStack,
          // The stack of parent contexts
    parent = stack[stack.length - 1]; // The parent containing the current list

    switch (token.type) {
      case '[':
        // Stack the current list quad and start a new quad with a blank node as subject
        this._saveContext('blank', this._graph, list = this._blankNode(), this.RDF_FIRST, this._subject = item = this._blankNode());

        next = this._readBlankNodeHead;
        break;

      case '(':
        // Stack the current list quad and start a new list
        this._saveContext('list', this._graph, list = this._blankNode(), this.RDF_FIRST, this.RDF_NIL);

        this._subject = null;
        break;

      case ')':
        // Closing the list; restore the parent context
        this._restoreContext(); // If this list is contained within a parent list, return the membership quad here.
        // This will be `<parent list element> rdf:first <this list>.`.


        if (stack.length !== 0 && stack[stack.length - 1].type === 'list') this._emit(this._subject, this._predicate, this._object, this._graph); // Was this list the parent's subject?

        if (this._predicate === null) {
          // The next token is the predicate
          next = this._readPredicate; // No list tail if this was an empty list

          if (this._subject === this.RDF_NIL) return next;
        } // The list was in the parent context's object
        else {
          next = this._getContextEndReader(); // No list tail if this was an empty list

          if (this._object === this.RDF_NIL) return next;
        } // Close the list by making the head nil


        list = this.RDF_NIL;
        break;

      case 'literal':
        // Regular literal, can still get a datatype or language
        if (token.prefix.length === 0) {
          this._literalValue = token.value;
          next = this._readListItemDataTypeOrLang;
        } // Pre-datatyped string literal (prefix stores the datatype)
        else {
          item = this._literal(token.value, this._namedNode(token.prefix));
          next = this._getContextEndReader();
        }

        break;

      case '{':
        // Start a new formula
        if (!this._n3Mode) return this._error('Unexpected graph', token);

        this._saveContext('formula', this._graph, this._subject, this._predicate, this._graph = this._blankNode());

        return this._readSubject;

      default:
        if ((item = this._readEntity(token)) === undefined) return;
    } // Create a new blank node if no item head was assigned yet


    if (list === null) this._subject = list = this._blankNode(); // Is this the first element of the list?

    if (previousList === null) {
      // This list is either the subject or the object of its parent
      if (parent.predicate === null) parent.subject = list;else parent.object = list;
    } else {
      // Continue the previous list with the current list
      this._emit(previousList, this.RDF_REST, list, this._graph);
    } // If an item was read, add it to the list


    if (item !== null) {
      // In N3 mode, the item might be a path
      if (this._n3Mode && (token.type === 'IRI' || token.type === 'prefixed')) {
        // Create a new context to add the item's path
        this._saveContext('item', this._graph, list, this.RDF_FIRST, item);

        this._subject = item, this._predicate = null; // _readPath will restore the context and output the item

        return this._getPathReader(this._readListItem);
      } // Output the item


      this._emit(list, this.RDF_FIRST, item, this._graph);
    }

    return next;
  } // ### `_readDataTypeOrLang` reads an _optional_ datatype or language


  _readDataTypeOrLang(token) {
    return this._completeObjectLiteral(token, false);
  } // ### `_readListItemDataTypeOrLang` reads an _optional_ datatype or language in a list


  _readListItemDataTypeOrLang(token) {
    return this._completeObjectLiteral(token, true);
  } // ### `_completeLiteral` completes a literal with an optional datatype or language


  _completeLiteral(token) {
    // Create a simple string literal by default
    let literal = this._literal(this._literalValue);

    switch (token.type) {
      // Create a datatyped literal
      case 'type':
      case 'typeIRI':
        const datatype = this._readEntity(token);

        if (datatype === undefined) return; // No datatype means an error occurred

        literal = this._literal(this._literalValue, datatype);
        token = null;
        break;
      // Create a language-tagged string

      case 'langcode':
        literal = this._literal(this._literalValue, token.value);
        token = null;
        break;
    }

    return {
      token,
      literal
    };
  } // Completes a literal in subject position


  _completeSubjectLiteral(token) {
    this._subject = this._completeLiteral(token).literal;
    return this._readPredicateOrNamedGraph;
  } // Completes a literal in object position


  _completeObjectLiteral(token, listItem) {
    const completed = this._completeLiteral(token);

    if (!completed) return;
    this._object = completed.literal; // If this literal was part of a list, write the item
    // (we could also check the context stack, but passing in a flag is faster)

    if (listItem) this._emit(this._subject, this.RDF_FIRST, this._object, this._graph); // If the token was consumed, continue with the rest of the input

    if (completed.token === null) return this._getContextEndReader(); // Otherwise, consume the token now
    else {
      this._readCallback = this._getContextEndReader();
      return this._readCallback(completed.token);
    }
  } // ### `_readFormulaTail` reads the end of a formula


  _readFormulaTail(token) {
    if (token.type !== '}') return this._readPunctuation(token); // Store the last quad of the formula

    if (this._subject !== null) this._emit(this._subject, this._predicate, this._object, this._graph); // Restore the parent context containing this formula

    this._restoreContext(); // If the formula was the subject, continue reading the predicate.
    // If the formula was the object, read punctuation.


    return this._object === null ? this._readPredicate : this._getContextEndReader();
  } // ### `_readPunctuation` reads punctuation between quads or quad parts


  _readPunctuation(token) {
    let next,
        graph = this._graph;
    const subject = this._subject,
          inversePredicate = this._inversePredicate;

    switch (token.type) {
      // A closing brace ends a graph
      case '}':
        if (this._graph === null) return this._error('Unexpected graph closing', token);
        if (this._n3Mode) return this._readFormulaTail(token);
        this._graph = null;
      // A dot just ends the statement, without sharing anything with the next

      case '.':
        this._subject = null;
        next = this._contextStack.length ? this._readSubject : this._readInTopContext;
        if (inversePredicate) this._inversePredicate = false;
        break;
      // Semicolon means the subject is shared; predicate and object are different

      case ';':
        next = this._readPredicate;
        break;
      // Comma means both the subject and predicate are shared; the object is different

      case ',':
        next = this._readObject;
        break;

      default:
        // An entity means this is a quad (only allowed if not already inside a graph)
        if (this._supportsQuads && this._graph === null && (graph = this._readEntity(token)) !== undefined) {
          next = this._readQuadPunctuation;
          break;
        }

        return this._error(`Expected punctuation to follow "${this._object.id}"`, token);
    } // A quad has been completed now, so return it


    if (subject !== null) {
      const predicate = this._predicate,
            object = this._object;
      if (!inversePredicate) this._emit(subject, predicate, object, graph);else this._emit(object, predicate, subject, graph);
    }

    return next;
  } // ### `_readBlankNodePunctuation` reads punctuation in a blank node


  _readBlankNodePunctuation(token) {
    let next;

    switch (token.type) {
      // Semicolon means the subject is shared; predicate and object are different
      case ';':
        next = this._readPredicate;
        break;
      // Comma means both the subject and predicate are shared; the object is different

      case ',':
        next = this._readObject;
        break;

      default:
        return this._error(`Expected punctuation to follow "${this._object.id}"`, token);
    } // A quad has been completed now, so return it


    this._emit(this._subject, this._predicate, this._object, this._graph);

    return next;
  } // ### `_readQuadPunctuation` reads punctuation after a quad


  _readQuadPunctuation(token) {
    if (token.type !== '.') return this._error('Expected dot to follow quad', token);
    return this._readInTopContext;
  } // ### `_readPrefix` reads the prefix of a prefix declaration


  _readPrefix(token) {
    if (token.type !== 'prefix') return this._error('Expected prefix to follow @prefix', token);
    this._prefix = token.value;
    return this._readPrefixIRI;
  } // ### `_readPrefixIRI` reads the IRI of a prefix declaration


  _readPrefixIRI(token) {
    if (token.type !== 'IRI') return this._error(`Expected IRI to follow prefix "${this._prefix}:"`, token);

    const prefixNode = this._readEntity(token);

    this._prefixes[this._prefix] = prefixNode.value;

    this._prefixCallback(this._prefix, prefixNode);

    return this._readDeclarationPunctuation;
  } // ### `_readBaseIRI` reads the IRI of a base declaration


  _readBaseIRI(token) {
    const iri = token.type === 'IRI' && this._resolveIRI(token.value);

    if (!iri) return this._error('Expected valid IRI to follow base declaration', token);

    this._setBase(iri);

    return this._readDeclarationPunctuation;
  } // ### `_readNamedGraphLabel` reads the label of a named graph


  _readNamedGraphLabel(token) {
    switch (token.type) {
      case 'IRI':
      case 'blank':
      case 'prefixed':
        return this._readSubject(token), this._readGraph;

      case '[':
        return this._readNamedGraphBlankLabel;

      default:
        return this._error('Invalid graph label', token);
    }
  } // ### `_readNamedGraphLabel` reads a blank node label of a named graph


  _readNamedGraphBlankLabel(token) {
    if (token.type !== ']') return this._error('Invalid graph label', token);
    this._subject = this._blankNode();
    return this._readGraph;
  } // ### `_readDeclarationPunctuation` reads the punctuation of a declaration


  _readDeclarationPunctuation(token) {
    // SPARQL-style declarations don't have punctuation
    if (this._sparqlStyle) {
      this._sparqlStyle = false;
      return this._readInTopContext(token);
    }

    if (token.type !== '.') return this._error('Expected declaration to end with a dot', token);
    return this._readInTopContext;
  } // Reads a list of quantified symbols from a @forSome or @forAll statement


  _readQuantifierList(token) {
    let entity;

    switch (token.type) {
      case 'IRI':
      case 'prefixed':
        if ((entity = this._readEntity(token, true)) !== undefined) break;

      default:
        return this._error(`Unexpected ${token.type}`, token);
    } // Without explicit quantifiers, map entities to a quantified entity


    if (!this._explicitQuantifiers) this._quantified[entity.id] = this._quantifier(this._blankNode().value); // With explicit quantifiers, output the reified quantifier
    else {
      // If this is the first item, start a new quantifier list
      if (this._subject === null) this._emit(this._graph || this.DEFAULTGRAPH, this._predicate, this._subject = this._blankNode(), this.QUANTIFIERS_GRAPH); // Otherwise, continue the previous list
      else this._emit(this._subject, this.RDF_REST, this._subject = this._blankNode(), this.QUANTIFIERS_GRAPH); // Output the list item

      this._emit(this._subject, this.RDF_FIRST, entity, this.QUANTIFIERS_GRAPH);
    }
    return this._readQuantifierPunctuation;
  } // Reads punctuation from a @forSome or @forAll statement


  _readQuantifierPunctuation(token) {
    // Read more quantifiers
    if (token.type === ',') return this._readQuantifierList; // End of the quantifier list
    else {
      // With explicit quantifiers, close the quantifier list
      if (this._explicitQuantifiers) {
        this._emit(this._subject, this.RDF_REST, this.RDF_NIL, this.QUANTIFIERS_GRAPH);

        this._subject = null;
      } // Read a dot


      this._readCallback = this._getContextEndReader();
      return this._readCallback(token);
    }
  } // ### `_getPathReader` reads a potential path and then resumes with the given function


  _getPathReader(afterPath) {
    this._afterPath = afterPath;
    return this._readPath;
  } // ### `_readPath` reads a potential path


  _readPath(token) {
    switch (token.type) {
      // Forward path
      case '!':
        return this._readForwardPath;
      // Backward path

      case '^':
        return this._readBackwardPath;
      // Not a path; resume reading where we left off

      default:
        const stack = this._contextStack,
              parent = stack.length && stack[stack.length - 1]; // If we were reading a list item, we still need to output it

        if (parent && parent.type === 'item') {
          // The list item is the remaining subejct after reading the path
          const item = this._subject; // Switch back to the context of the list

          this._restoreContext(); // Output the list item


          this._emit(this._subject, this.RDF_FIRST, item, this._graph);
        }

        return this._afterPath(token);
    }
  } // ### `_readForwardPath` reads a '!' path


  _readForwardPath(token) {
    let subject, predicate;

    const object = this._blankNode(); // The next token is the predicate


    if ((predicate = this._readEntity(token)) === undefined) return; // If we were reading a subject, replace the subject by the path's object

    if (this._predicate === null) subject = this._subject, this._subject = object; // If we were reading an object, replace the subject by the path's object
    else subject = this._object, this._object = object; // Emit the path's current quad and read its next section

    this._emit(subject, predicate, object, this._graph);

    return this._readPath;
  } // ### `_readBackwardPath` reads a '^' path


  _readBackwardPath(token) {
    const subject = this._blankNode();

    let predicate, object; // The next token is the predicate

    if ((predicate = this._readEntity(token)) === undefined) return; // If we were reading a subject, replace the subject by the path's subject

    if (this._predicate === null) object = this._subject, this._subject = subject; // If we were reading an object, replace the subject by the path's subject
    else object = this._object, this._object = subject; // Emit the path's current quad and read its next section

    this._emit(subject, predicate, object, this._graph);

    return this._readPath;
  } // ### `_readRDFStarTailOrGraph` reads the graph of a nested RDF* quad or the end of a nested RDF* triple


  _readRDFStarTailOrGraph(token) {
    if (token.type !== '>>') {
      // An entity means this is a quad (only allowed if not already inside a graph)
      if (this._supportsQuads && this._graph === null && (this._graph = this._readEntity(token)) !== undefined) return this._readRDFStarTail;
      return this._error(`Expected >> to follow "${this._object.id}"`, token);
    }

    return this._readRDFStarTail(token);
  } // ### `_readRDFStarTail` reads the end of a nested RDF* triple


  _readRDFStarTail(token) {
    if (token.type !== '>>') return this._error(`Expected >> but got ${token.type}`, token); // Read the quad and restore the previous context

    const quad = this._quad(this._subject, this._predicate, this._object, this._graph || this.DEFAULTGRAPH);

    this._restoreContext(); // If the triple was the subject, continue by reading the predicate.


    if (this._subject === null) {
      this._subject = quad;
      return this._readPredicate;
    } // If the triple was the object, read context end.
    else {
      this._object = quad;
      return this._getContextEndReader();
    }
  } // ### `_getContextEndReader` gets the next reader function at the end of a context


  _getContextEndReader() {
    const contextStack = this._contextStack;
    if (!contextStack.length) return this._readPunctuation;

    switch (contextStack[contextStack.length - 1].type) {
      case 'blank':
        return this._readBlankNodeTail;

      case 'list':
        return this._readListItem;

      case 'formula':
        return this._readFormulaTail;

      case '<<':
        return this._readRDFStarTailOrGraph;
    }
  } // ### `_emit` sends a quad through the callback


  _emit(subject, predicate, object, graph) {
    this._callback(null, this._quad(subject, predicate, object, graph || this.DEFAULTGRAPH));
  } // ### `_error` emits an error message through the callback


  _error(message, token) {
    const err = new Error(`${message} on line ${token.line}.`);
    err.context = {
      token: token,
      line: token.line,
      previousToken: this._lexer.previousToken
    };

    this._callback(err);

    this._callback = noop;
  } // ### `_resolveIRI` resolves an IRI against the base path


  _resolveIRI(iri) {
    return /^[a-z][a-z0-9+.-]*:/i.test(iri) ? iri : this._resolveRelativeIRI(iri);
  } // ### `_resolveRelativeIRI` resolves an IRI against the base path,
  // assuming that a base path has been set and that the IRI is indeed relative


  _resolveRelativeIRI(iri) {
    // An empty relative IRI indicates the base IRI
    if (!iri.length) return this._base; // Decide resolving strategy based in the first character

    switch (iri[0]) {
      // Resolve relative fragment IRIs against the base IRI
      case '#':
        return this._base + iri;
      // Resolve relative query string IRIs by replacing the query string

      case '?':
        return this._base.replace(/(?:\?.*)?$/, iri);
      // Resolve root-relative IRIs at the root of the base IRI

      case '/':
        // Resolve scheme-relative IRIs to the scheme
        return (iri[1] === '/' ? this._baseScheme : this._baseRoot) + this._removeDotSegments(iri);
      // Resolve all other IRIs at the base IRI's path

      default:
        // Relative IRIs cannot contain a colon in the first path segment
        return /^[^/:]*:/.test(iri) ? null : this._removeDotSegments(this._basePath + iri);
    }
  } // ### `_removeDotSegments` resolves './' and '../' path segments in an IRI as per RFC3986


  _removeDotSegments(iri) {
    // Don't modify the IRI if it does not contain any dot segments
    if (!/(^|\/)\.\.?($|[/#?])/.test(iri)) return iri; // Start with an imaginary slash before the IRI in order to resolve trailing './' and '../'

    const length = iri.length;
    let result = '',
        i = -1,
        pathStart = -1,
        segmentStart = 0,
        next = '/';

    while (i < length) {
      switch (next) {
        // The path starts with the first slash after the authority
        case ':':
          if (pathStart < 0) {
            // Skip two slashes before the authority
            if (iri[++i] === '/' && iri[++i] === '/') // Skip to slash after the authority
              while ((pathStart = i + 1) < length && iri[pathStart] !== '/') i = pathStart;
          }

          break;
        // Don't modify a query string or fragment

        case '?':
        case '#':
          i = length;
          break;
        // Handle '/.' or '/..' path segments

        case '/':
          if (iri[i + 1] === '.') {
            next = iri[++i + 1];

            switch (next) {
              // Remove a '/.' segment
              case '/':
                result += iri.substring(segmentStart, i - 1);
                segmentStart = i + 1;
                break;
              // Remove a trailing '/.' segment

              case undefined:
              case '?':
              case '#':
                return result + iri.substring(segmentStart, i) + iri.substr(i + 1);
              // Remove a '/..' segment

              case '.':
                next = iri[++i + 1];

                if (next === undefined || next === '/' || next === '?' || next === '#') {
                  result += iri.substring(segmentStart, i - 2); // Try to remove the parent path from result

                  if ((segmentStart = result.lastIndexOf('/')) >= pathStart) result = result.substr(0, segmentStart); // Remove a trailing '/..' segment

                  if (next !== '/') return `${result}/${iri.substr(i + 1)}`;
                  segmentStart = i + 1;
                }

            }
          }

      }

      next = iri[++i];
    }

    return result + iri.substring(segmentStart);
  } // ## Public methods
  // ### `parse` parses the N3 input and emits each parsed quad through the callback


  parse(input, quadCallback, prefixCallback) {
    // The read callback is the next function to be executed when a token arrives.
    // We start reading in the top context.
    this._readCallback = this._readInTopContext;
    this._sparqlStyle = false;
    this._prefixes = Object.create(null);
    this._prefixes._ = this._blankNodePrefix ? this._blankNodePrefix.substr(2) : `b${blankNodePrefix++}_`;
    this._prefixCallback = prefixCallback || noop;
    this._inversePredicate = false;
    this._quantified = Object.create(null); // Parse synchronously if no quad callback is given

    if (!quadCallback) {
      const quads = [];
      let error;

      this._callback = (e, t) => {
        e ? error = e : t && quads.push(t);
      };

      this._lexer.tokenize(input).every(token => {
        return this._readCallback = this._readCallback(token);
      });

      if (error) throw error;
      return quads;
    } // Parse asynchronously otherwise, executing the read callback when a token arrives


    this._callback = quadCallback;

    this._lexer.tokenize(input, (error, token) => {
      if (error !== null) this._callback(error), this._callback = noop;else if (this._readCallback) this._readCallback = this._readCallback(token);
    });
  }

} // The empty function


exports.default = N3Parser;

function noop() {} // Initializes the parser with the given data factory


function initDataFactory(parser, factory) {
  // Set factory methods
  const namedNode = factory.namedNode;
  parser._namedNode = namedNode;
  parser._blankNode = factory.blankNode;
  parser._literal = factory.literal;
  parser._variable = factory.variable;
  parser._quad = factory.quad;
  parser.DEFAULTGRAPH = factory.defaultGraph(); // Set common named nodes

  parser.RDF_FIRST = namedNode(_IRIs.default.rdf.first);
  parser.RDF_REST = namedNode(_IRIs.default.rdf.rest);
  parser.RDF_NIL = namedNode(_IRIs.default.rdf.nil);
  parser.N3_FORALL = namedNode(_IRIs.default.r.forAll);
  parser.N3_FORSOME = namedNode(_IRIs.default.r.forSome);
  parser.ABBREVIATIONS = {
    'a': namedNode(_IRIs.default.rdf.type),
    '=': namedNode(_IRIs.default.owl.sameAs),
    '>': namedNode(_IRIs.default.log.implies)
  };
  parser.QUANTIFIERS_GRAPH = namedNode('urn:n3:quantifiers');
}

initDataFactory(N3Parser.prototype, _N3DataFactory.default);

},{"./IRIs":125,"./N3DataFactory":126,"./N3Lexer":127}],129:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _N3DataFactory = _interopRequireWildcard(require("./N3DataFactory"));

var _readableStream = require("readable-stream");

var _IRIs = _interopRequireDefault(require("./IRIs"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

// **N3Store** objects store N3 quads by graph in memory.
// ## Constructor
class N3Store {
  constructor(quads, options) {
    // The number of quads is initially zero
    this._size = 0; // `_graphs` contains subject, predicate, and object indexes per graph

    this._graphs = Object.create(null); // `_ids` maps entities such as `http://xmlns.com/foaf/0.1/name` to numbers,
    // saving memory by using only numbers as keys in `_graphs`

    this._id = 0;
    this._ids = Object.create(null);
    this._ids['><'] = 0; // dummy entry, so the first actual key is non-zero

    this._entities = Object.create(null); // inverse of `_ids`
    // `_blankNodeIndex` is the index of the last automatically named blank node

    this._blankNodeIndex = 0; // Shift parameters if `quads` is not given

    if (!options && quads && !quads[0]) options = quads, quads = null;
    options = options || {};
    this._factory = options.factory || _N3DataFactory.default; // Add quads if passed

    if (quads) this.addQuads(quads);
  } // ## Public properties
  // ### `size` returns the number of quads in the store


  get size() {
    // Return the quad count if if was cached
    let size = this._size;
    if (size !== null) return size; // Calculate the number of quads by counting to the deepest level

    size = 0;
    const graphs = this._graphs;
    let subjects, subject;

    for (const graphKey in graphs) for (const subjectKey in subjects = graphs[graphKey].subjects) for (const predicateKey in subject = subjects[subjectKey]) size += Object.keys(subject[predicateKey]).length;

    return this._size = size;
  } // ## Private methods
  // ### `_addToIndex` adds a quad to a three-layered index.
  // Returns if the index has changed, if the entry did not already exist.


  _addToIndex(index0, key0, key1, key2) {
    // Create layers as necessary
    const index1 = index0[key0] || (index0[key0] = {});
    const index2 = index1[key1] || (index1[key1] = {}); // Setting the key to _any_ value signals the presence of the quad

    const existed = (key2 in index2);
    if (!existed) index2[key2] = null;
    return !existed;
  } // ### `_removeFromIndex` removes a quad from a three-layered index


  _removeFromIndex(index0, key0, key1, key2) {
    // Remove the quad from the index
    const index1 = index0[key0],
          index2 = index1[key1];
    delete index2[key2]; // Remove intermediary index layers if they are empty

    for (const key in index2) return;

    delete index1[key1];

    for (const key in index1) return;

    delete index0[key0];
  } // ### `_findInIndex` finds a set of quads in a three-layered index.
  // The index base is `index0` and the keys at each level are `key0`, `key1`, and `key2`.
  // Any of these keys can be undefined, which is interpreted as a wildcard.
  // `name0`, `name1`, and `name2` are the names of the keys at each level,
  // used when reconstructing the resulting quad
  // (for instance: _subject_, _predicate_, and _object_).
  // Finally, `graph` will be the graph of the created quads.
  // If `callback` is given, each result is passed through it
  // and iteration halts when it returns truthy for any quad.
  // If instead `array` is given, each result is added to the array.


  _findInIndex(index0, key0, key1, key2, name0, name1, name2, graph, callback, array) {
    let tmp, index1, index2; // Depending on the number of variables, keys or reverse index are faster

    const varCount = !key0 + !key1 + !key2,
          entityKeys = varCount > 1 ? Object.keys(this._ids) : this._entities; // If a key is specified, use only that part of index 0.

    if (key0) (tmp = index0, index0 = {})[key0] = tmp[key0];

    for (const value0 in index0) {
      const entity0 = entityKeys[value0];

      if (index1 = index0[value0]) {
        // If a key is specified, use only that part of index 1.
        if (key1) (tmp = index1, index1 = {})[key1] = tmp[key1];

        for (const value1 in index1) {
          const entity1 = entityKeys[value1];

          if (index2 = index1[value1]) {
            // If a key is specified, use only that part of index 2, if it exists.
            const values = key2 ? key2 in index2 ? [key2] : [] : Object.keys(index2); // Create quads for all items found in index 2.

            for (let l = 0; l < values.length; l++) {
              const parts = {
                subject: null,
                predicate: null,
                object: null
              };
              parts[name0] = (0, _N3DataFactory.termFromId)(entity0, this._factory);
              parts[name1] = (0, _N3DataFactory.termFromId)(entity1, this._factory);
              parts[name2] = (0, _N3DataFactory.termFromId)(entityKeys[values[l]], this._factory);

              const quad = this._factory.quad(parts.subject, parts.predicate, parts.object, (0, _N3DataFactory.termFromId)(graph, this._factory));

              if (array) array.push(quad);else if (callback(quad)) return true;
            }
          }
        }
      }
    }

    return array;
  } // ### `_loop` executes the callback on all keys of index 0


  _loop(index0, callback) {
    for (const key0 in index0) callback(key0);
  } // ### `_loopByKey0` executes the callback on all keys of a certain entry in index 0


  _loopByKey0(index0, key0, callback) {
    let index1, key1;

    if (index1 = index0[key0]) {
      for (key1 in index1) callback(key1);
    }
  } // ### `_loopByKey1` executes the callback on given keys of all entries in index 0


  _loopByKey1(index0, key1, callback) {
    let key0, index1;

    for (key0 in index0) {
      index1 = index0[key0];
      if (index1[key1]) callback(key0);
    }
  } // ### `_loopBy2Keys` executes the callback on given keys of certain entries in index 2


  _loopBy2Keys(index0, key0, key1, callback) {
    let index1, index2, key2;

    if ((index1 = index0[key0]) && (index2 = index1[key1])) {
      for (key2 in index2) callback(key2);
    }
  } // ### `_countInIndex` counts matching quads in a three-layered index.
  // The index base is `index0` and the keys at each level are `key0`, `key1`, and `key2`.
  // Any of these keys can be undefined, which is interpreted as a wildcard.


  _countInIndex(index0, key0, key1, key2) {
    let count = 0,
        tmp,
        index1,
        index2; // If a key is specified, count only that part of index 0

    if (key0) (tmp = index0, index0 = {})[key0] = tmp[key0];

    for (const value0 in index0) {
      if (index1 = index0[value0]) {
        // If a key is specified, count only that part of index 1
        if (key1) (tmp = index1, index1 = {})[key1] = tmp[key1];

        for (const value1 in index1) {
          if (index2 = index1[value1]) {
            // If a key is specified, count the quad if it exists
            if (key2) key2 in index2 && count++; // Otherwise, count all quads
            else count += Object.keys(index2).length;
          }
        }
      }
    }

    return count;
  } // ### `_getGraphs` returns an array with the given graph,
  // or all graphs if the argument is null or undefined.


  _getGraphs(graph) {
    if (!isString(graph)) return this._graphs;
    const graphs = {};
    graphs[graph] = this._graphs[graph];
    return graphs;
  } // ### `_uniqueEntities` returns a function that accepts an entity ID
  // and passes the corresponding entity to callback if it hasn't occurred before.


  _uniqueEntities(callback) {
    const uniqueIds = Object.create(null);
    return id => {
      if (!(id in uniqueIds)) {
        uniqueIds[id] = true;
        callback((0, _N3DataFactory.termFromId)(this._entities[id], this._factory));
      }
    };
  } // ## Public methods
  // ### `add` adds the specified quad to the dataset.
  // Returns the dataset instance it was called on.
  // Existing quads, as defined in Quad.equals, will be ignored.


  add(quad) {
    this.addQuad(quad);
    return this;
  } // ### `addQuad` adds a new quad to the store.
  // Returns if the quad index has changed, if the quad did not already exist.


  addQuad(subject, predicate, object, graph) {
    // Shift arguments if a quad object is given instead of components
    if (!predicate) graph = subject.graph, object = subject.object, predicate = subject.predicate, subject = subject.subject; // Convert terms to internal string representation

    subject = (0, _N3DataFactory.termToId)(subject);
    predicate = (0, _N3DataFactory.termToId)(predicate);
    object = (0, _N3DataFactory.termToId)(object);
    graph = (0, _N3DataFactory.termToId)(graph); // Find the graph that will contain the triple

    let graphItem = this._graphs[graph]; // Create the graph if it doesn't exist yet

    if (!graphItem) {
      graphItem = this._graphs[graph] = {
        subjects: {},
        predicates: {},
        objects: {}
      }; // Freezing a graph helps subsequent `add` performance,
      // and properties will never be modified anyway

      Object.freeze(graphItem);
    } // Since entities can often be long IRIs, we avoid storing them in every index.
    // Instead, we have a separate index that maps entities to numbers,
    // which are then used as keys in the other indexes.


    const ids = this._ids;
    const entities = this._entities;
    subject = ids[subject] || (ids[entities[++this._id] = subject] = this._id);
    predicate = ids[predicate] || (ids[entities[++this._id] = predicate] = this._id);
    object = ids[object] || (ids[entities[++this._id] = object] = this._id);

    const changed = this._addToIndex(graphItem.subjects, subject, predicate, object);

    this._addToIndex(graphItem.predicates, predicate, object, subject);

    this._addToIndex(graphItem.objects, object, subject, predicate); // The cached quad count is now invalid


    this._size = null;
    return changed;
  } // ### `addQuads` adds multiple quads to the store


  addQuads(quads) {
    for (let i = 0; i < quads.length; i++) this.addQuad(quads[i]);
  } // ### `delete` removes the specified quad from the dataset.
  // Returns the dataset instance it was called on.


  delete(quad) {
    this.removeQuad(quad);
    return this;
  } // ### `has` determines whether a dataset includes a certain quad.
  // Returns true or false as appropriate.


  has(quad) {
    const quads = this.getQuads(quad.subject, quad.predicate, quad.object, quad.graph);
    return quads.length !== 0;
  } // ### `import` adds a stream of quads to the store


  import(stream) {
    stream.on('data', quad => {
      this.addQuad(quad);
    });
    return stream;
  } // ### `removeQuad` removes a quad from the store if it exists


  removeQuad(subject, predicate, object, graph) {
    // Shift arguments if a quad object is given instead of components
    if (!predicate) graph = subject.graph, object = subject.object, predicate = subject.predicate, subject = subject.subject; // Convert terms to internal string representation

    subject = (0, _N3DataFactory.termToId)(subject);
    predicate = (0, _N3DataFactory.termToId)(predicate);
    object = (0, _N3DataFactory.termToId)(object);
    graph = (0, _N3DataFactory.termToId)(graph); // Find internal identifiers for all components
    // and verify the quad exists.

    const ids = this._ids,
          graphs = this._graphs;
    let graphItem, subjects, predicates;
    if (!(subject = ids[subject]) || !(predicate = ids[predicate]) || !(object = ids[object]) || !(graphItem = graphs[graph]) || !(subjects = graphItem.subjects[subject]) || !(predicates = subjects[predicate]) || !(object in predicates)) return false; // Remove it from all indexes

    this._removeFromIndex(graphItem.subjects, subject, predicate, object);

    this._removeFromIndex(graphItem.predicates, predicate, object, subject);

    this._removeFromIndex(graphItem.objects, object, subject, predicate);

    if (this._size !== null) this._size--; // Remove the graph if it is empty

    for (subject in graphItem.subjects) return true;

    delete graphs[graph];
    return true;
  } // ### `removeQuads` removes multiple quads from the store


  removeQuads(quads) {
    for (let i = 0; i < quads.length; i++) this.removeQuad(quads[i]);
  } // ### `remove` removes a stream of quads from the store


  remove(stream) {
    stream.on('data', quad => {
      this.removeQuad(quad);
    });
    return stream;
  } // ### `removeMatches` removes all matching quads from the store
  // Setting any field to `undefined` or `null` indicates a wildcard.


  removeMatches(subject, predicate, object, graph) {
    const stream = new _readableStream.Readable({
      objectMode: true
    });

    stream._read = () => {
      for (const quad of this.getQuads(subject, predicate, object, graph)) stream.push(quad);

      stream.push(null);
    };

    return this.remove(stream);
  } // ### `deleteGraph` removes all triples with the given graph from the store


  deleteGraph(graph) {
    return this.removeMatches(null, null, null, graph);
  } // ### `getQuads` returns an array of quads matching a pattern.
  // Setting any field to `undefined` or `null` indicates a wildcard.


  getQuads(subject, predicate, object, graph) {
    // Convert terms to internal string representation
    subject = subject && (0, _N3DataFactory.termToId)(subject);
    predicate = predicate && (0, _N3DataFactory.termToId)(predicate);
    object = object && (0, _N3DataFactory.termToId)(object);
    graph = graph && (0, _N3DataFactory.termToId)(graph);

    const quads = [],
          graphs = this._getGraphs(graph),
          ids = this._ids;

    let content, subjectId, predicateId, objectId; // Translate IRIs to internal index keys.

    if (isString(subject) && !(subjectId = ids[subject]) || isString(predicate) && !(predicateId = ids[predicate]) || isString(object) && !(objectId = ids[object])) return quads;

    for (const graphId in graphs) {
      // Only if the specified graph contains triples, there can be results
      if (content = graphs[graphId]) {
        // Choose the optimal index, based on what fields are present
        if (subjectId) {
          if (objectId) // If subject and object are given, the object index will be the fastest
            this._findInIndex(content.objects, objectId, subjectId, predicateId, 'object', 'subject', 'predicate', graphId, null, quads);else // If only subject and possibly predicate are given, the subject index will be the fastest
            this._findInIndex(content.subjects, subjectId, predicateId, null, 'subject', 'predicate', 'object', graphId, null, quads);
        } else if (predicateId) // If only predicate and possibly object are given, the predicate index will be the fastest
          this._findInIndex(content.predicates, predicateId, objectId, null, 'predicate', 'object', 'subject', graphId, null, quads);else if (objectId) // If only object is given, the object index will be the fastest
          this._findInIndex(content.objects, objectId, null, null, 'object', 'subject', 'predicate', graphId, null, quads);else // If nothing is given, iterate subjects and predicates first
          this._findInIndex(content.subjects, null, null, null, 'subject', 'predicate', 'object', graphId, null, quads);
      }
    }

    return quads;
  } // ### `match` returns a new dataset that is comprised of all quads in the current instance matching the given arguments.
  // The logic described in Quad Matching is applied for each quad in this dataset to check if it should be included in the output dataset.
  // Note: This method always returns a new DatasetCore, even if that dataset contains no quads.
  // Note: Since a DatasetCore is an unordered set, the order of the quads within the returned sequence is arbitrary.
  // Setting any field to `undefined` or `null` indicates a wildcard.
  // For backwards compatibility, the object return also implements the Readable stream interface.


  match(subject, predicate, object, graph) {
    return new DatasetCoreAndReadableStream(this, subject, predicate, object, graph);
  } // ### `countQuads` returns the number of quads matching a pattern.
  // Setting any field to `undefined` or `null` indicates a wildcard.


  countQuads(subject, predicate, object, graph) {
    // Convert terms to internal string representation
    subject = subject && (0, _N3DataFactory.termToId)(subject);
    predicate = predicate && (0, _N3DataFactory.termToId)(predicate);
    object = object && (0, _N3DataFactory.termToId)(object);
    graph = graph && (0, _N3DataFactory.termToId)(graph);

    const graphs = this._getGraphs(graph),
          ids = this._ids;

    let count = 0,
        content,
        subjectId,
        predicateId,
        objectId; // Translate IRIs to internal index keys.

    if (isString(subject) && !(subjectId = ids[subject]) || isString(predicate) && !(predicateId = ids[predicate]) || isString(object) && !(objectId = ids[object])) return 0;

    for (const graphId in graphs) {
      // Only if the specified graph contains triples, there can be results
      if (content = graphs[graphId]) {
        // Choose the optimal index, based on what fields are present
        if (subject) {
          if (object) // If subject and object are given, the object index will be the fastest
            count += this._countInIndex(content.objects, objectId, subjectId, predicateId);else // If only subject and possibly predicate are given, the subject index will be the fastest
            count += this._countInIndex(content.subjects, subjectId, predicateId, objectId);
        } else if (predicate) {
          // If only predicate and possibly object are given, the predicate index will be the fastest
          count += this._countInIndex(content.predicates, predicateId, objectId, subjectId);
        } else {
          // If only object is possibly given, the object index will be the fastest
          count += this._countInIndex(content.objects, objectId, subjectId, predicateId);
        }
      }
    }

    return count;
  } // ### `forEach` executes the callback on all quads.
  // Setting any field to `undefined` or `null` indicates a wildcard.


  forEach(callback, subject, predicate, object, graph) {
    this.some(quad => {
      callback(quad);
      return false;
    }, subject, predicate, object, graph);
  } // ### `every` executes the callback on all quads,
  // and returns `true` if it returns truthy for all them.
  // Setting any field to `undefined` or `null` indicates a wildcard.


  every(callback, subject, predicate, object, graph) {
    let some = false;
    const every = !this.some(quad => {
      some = true;
      return !callback(quad);
    }, subject, predicate, object, graph);
    return some && every;
  } // ### `some` executes the callback on all quads,
  // and returns `true` if it returns truthy for any of them.
  // Setting any field to `undefined` or `null` indicates a wildcard.


  some(callback, subject, predicate, object, graph) {
    // Convert terms to internal string representation
    subject = subject && (0, _N3DataFactory.termToId)(subject);
    predicate = predicate && (0, _N3DataFactory.termToId)(predicate);
    object = object && (0, _N3DataFactory.termToId)(object);
    graph = graph && (0, _N3DataFactory.termToId)(graph);

    const graphs = this._getGraphs(graph),
          ids = this._ids;

    let content, subjectId, predicateId, objectId; // Translate IRIs to internal index keys.

    if (isString(subject) && !(subjectId = ids[subject]) || isString(predicate) && !(predicateId = ids[predicate]) || isString(object) && !(objectId = ids[object])) return false;

    for (const graphId in graphs) {
      // Only if the specified graph contains triples, there can be results
      if (content = graphs[graphId]) {
        // Choose the optimal index, based on what fields are present
        if (subjectId) {
          if (objectId) {
            // If subject and object are given, the object index will be the fastest
            if (this._findInIndex(content.objects, objectId, subjectId, predicateId, 'object', 'subject', 'predicate', graphId, callback, null)) return true;
          } else // If only subject and possibly predicate are given, the subject index will be the fastest
            if (this._findInIndex(content.subjects, subjectId, predicateId, null, 'subject', 'predicate', 'object', graphId, callback, null)) return true;
        } else if (predicateId) {
          // If only predicate and possibly object are given, the predicate index will be the fastest
          if (this._findInIndex(content.predicates, predicateId, objectId, null, 'predicate', 'object', 'subject', graphId, callback, null)) {
            return true;
          }
        } else if (objectId) {
          // If only object is given, the object index will be the fastest
          if (this._findInIndex(content.objects, objectId, null, null, 'object', 'subject', 'predicate', graphId, callback, null)) {
            return true;
          }
        } else // If nothing is given, iterate subjects and predicates first
          if (this._findInIndex(content.subjects, null, null, null, 'subject', 'predicate', 'object', graphId, callback, null)) {
            return true;
          }
      }
    }

    return false;
  } // ### `getSubjects` returns all subjects that match the pattern.
  // Setting any field to `undefined` or `null` indicates a wildcard.


  getSubjects(predicate, object, graph) {
    const results = [];
    this.forSubjects(s => {
      results.push(s);
    }, predicate, object, graph);
    return results;
  } // ### `forSubjects` executes the callback on all subjects that match the pattern.
  // Setting any field to `undefined` or `null` indicates a wildcard.


  forSubjects(callback, predicate, object, graph) {
    // Convert terms to internal string representation
    predicate = predicate && (0, _N3DataFactory.termToId)(predicate);
    object = object && (0, _N3DataFactory.termToId)(object);
    graph = graph && (0, _N3DataFactory.termToId)(graph);

    const ids = this._ids,
          graphs = this._getGraphs(graph);

    let content, predicateId, objectId;
    callback = this._uniqueEntities(callback); // Translate IRIs to internal index keys.

    if (isString(predicate) && !(predicateId = ids[predicate]) || isString(object) && !(objectId = ids[object])) return;

    for (graph in graphs) {
      // Only if the specified graph contains triples, there can be results
      if (content = graphs[graph]) {
        // Choose optimal index based on which fields are wildcards
        if (predicateId) {
          if (objectId) // If predicate and object are given, the POS index is best.
            this._loopBy2Keys(content.predicates, predicateId, objectId, callback);else // If only predicate is given, the SPO index is best.
            this._loopByKey1(content.subjects, predicateId, callback);
        } else if (objectId) // If only object is given, the OSP index is best.
          this._loopByKey0(content.objects, objectId, callback);else // If no params given, iterate all the subjects
          this._loop(content.subjects, callback);
      }
    }
  } // ### `getPredicates` returns all predicates that match the pattern.
  // Setting any field to `undefined` or `null` indicates a wildcard.


  getPredicates(subject, object, graph) {
    const results = [];
    this.forPredicates(p => {
      results.push(p);
    }, subject, object, graph);
    return results;
  } // ### `forPredicates` executes the callback on all predicates that match the pattern.
  // Setting any field to `undefined` or `null` indicates a wildcard.


  forPredicates(callback, subject, object, graph) {
    // Convert terms to internal string representation
    subject = subject && (0, _N3DataFactory.termToId)(subject);
    object = object && (0, _N3DataFactory.termToId)(object);
    graph = graph && (0, _N3DataFactory.termToId)(graph);

    const ids = this._ids,
          graphs = this._getGraphs(graph);

    let content, subjectId, objectId;
    callback = this._uniqueEntities(callback); // Translate IRIs to internal index keys.

    if (isString(subject) && !(subjectId = ids[subject]) || isString(object) && !(objectId = ids[object])) return;

    for (graph in graphs) {
      // Only if the specified graph contains triples, there can be results
      if (content = graphs[graph]) {
        // Choose optimal index based on which fields are wildcards
        if (subjectId) {
          if (objectId) // If subject and object are given, the OSP index is best.
            this._loopBy2Keys(content.objects, objectId, subjectId, callback);else // If only subject is given, the SPO index is best.
            this._loopByKey0(content.subjects, subjectId, callback);
        } else if (objectId) // If only object is given, the POS index is best.
          this._loopByKey1(content.predicates, objectId, callback);else // If no params given, iterate all the predicates.
          this._loop(content.predicates, callback);
      }
    }
  } // ### `getObjects` returns all objects that match the pattern.
  // Setting any field to `undefined` or `null` indicates a wildcard.


  getObjects(subject, predicate, graph) {
    const results = [];
    this.forObjects(o => {
      results.push(o);
    }, subject, predicate, graph);
    return results;
  } // ### `forObjects` executes the callback on all objects that match the pattern.
  // Setting any field to `undefined` or `null` indicates a wildcard.


  forObjects(callback, subject, predicate, graph) {
    // Convert terms to internal string representation
    subject = subject && (0, _N3DataFactory.termToId)(subject);
    predicate = predicate && (0, _N3DataFactory.termToId)(predicate);
    graph = graph && (0, _N3DataFactory.termToId)(graph);

    const ids = this._ids,
          graphs = this._getGraphs(graph);

    let content, subjectId, predicateId;
    callback = this._uniqueEntities(callback); // Translate IRIs to internal index keys.

    if (isString(subject) && !(subjectId = ids[subject]) || isString(predicate) && !(predicateId = ids[predicate])) return;

    for (graph in graphs) {
      // Only if the specified graph contains triples, there can be results
      if (content = graphs[graph]) {
        // Choose optimal index based on which fields are wildcards
        if (subjectId) {
          if (predicateId) // If subject and predicate are given, the SPO index is best.
            this._loopBy2Keys(content.subjects, subjectId, predicateId, callback);else // If only subject is given, the OSP index is best.
            this._loopByKey1(content.objects, subjectId, callback);
        } else if (predicateId) // If only predicate is given, the POS index is best.
          this._loopByKey0(content.predicates, predicateId, callback);else // If no params given, iterate all the objects.
          this._loop(content.objects, callback);
      }
    }
  } // ### `getGraphs` returns all graphs that match the pattern.
  // Setting any field to `undefined` or `null` indicates a wildcard.


  getGraphs(subject, predicate, object) {
    const results = [];
    this.forGraphs(g => {
      results.push(g);
    }, subject, predicate, object);
    return results;
  } // ### `forGraphs` executes the callback on all graphs that match the pattern.
  // Setting any field to `undefined` or `null` indicates a wildcard.


  forGraphs(callback, subject, predicate, object) {
    for (const graph in this._graphs) {
      this.some(quad => {
        callback(quad.graph);
        return true; // Halt iteration of some()
      }, subject, predicate, object, graph);
    }
  } // ### `createBlankNode` creates a new blank node, returning its name


  createBlankNode(suggestedName) {
    let name, index; // Generate a name based on the suggested name

    if (suggestedName) {
      name = suggestedName = `_:${suggestedName}`, index = 1;

      while (this._ids[name]) name = suggestedName + index++;
    } // Generate a generic blank node name
    else {
      do {
        name = `_:b${this._blankNodeIndex++}`;
      } while (this._ids[name]);
    } // Add the blank node to the entities, avoiding the generation of duplicates


    this._ids[name] = ++this._id;
    this._entities[this._id] = name;
    return this._factory.blankNode(name.substr(2));
  } // ### `extractLists` finds and removes all list triples
  // and returns the items per list.


  extractLists({
    remove = false,
    ignoreErrors = false
  } = {}) {
    const lists = {}; // has scalar keys so could be a simple Object

    const onError = ignoreErrors ? () => true : (node, message) => {
      throw new Error(`${node.value} ${message}`);
    }; // Traverse each list from its tail

    const tails = this.getQuads(null, _IRIs.default.rdf.rest, _IRIs.default.rdf.nil, null);
    const toRemove = remove ? [...tails] : [];
    tails.forEach(tailQuad => {
      const items = []; // the members found as objects of rdf:first quads

      let malformed = false; // signals whether the current list is malformed

      let head; // the head of the list (_:b1 in above example)

      let headPos; // set to subject or object when head is set

      const graph = tailQuad.graph; // make sure list is in exactly one graph
      // Traverse the list from tail to end

      let current = tailQuad.subject;

      while (current && !malformed) {
        const objectQuads = this.getQuads(null, null, current, null);
        const subjectQuads = this.getQuads(current, null, null, null);
        let quad,
            first = null,
            rest = null,
            parent = null; // Find the first and rest of this list node

        for (let i = 0; i < subjectQuads.length && !malformed; i++) {
          quad = subjectQuads[i];
          if (!quad.graph.equals(graph)) malformed = onError(current, 'not confined to single graph');else if (head) malformed = onError(current, 'has non-list arcs out'); // one rdf:first
          else if (quad.predicate.value === _IRIs.default.rdf.first) {
            if (first) malformed = onError(current, 'has multiple rdf:first arcs');else toRemove.push(first = quad);
          } // one rdf:rest
          else if (quad.predicate.value === _IRIs.default.rdf.rest) {
            if (rest) malformed = onError(current, 'has multiple rdf:rest arcs');else toRemove.push(rest = quad);
          } // alien triple
          else if (objectQuads.length) malformed = onError(current, 'can\'t be subject and object');else {
            head = quad; // e.g. { (1 2 3) :p :o }

            headPos = 'subject';
          }
        } // { :s :p (1 2) } arrives here with no head
        // { (1 2) :p :o } arrives here with head set to the list.


        for (let i = 0; i < objectQuads.length && !malformed; ++i) {
          quad = objectQuads[i];
          if (head) malformed = onError(current, 'can\'t have coreferences'); // one rdf:rest
          else if (quad.predicate.value === _IRIs.default.rdf.rest) {
            if (parent) malformed = onError(current, 'has incoming rdf:rest arcs');else parent = quad;
          } else {
            head = quad; // e.g. { :s :p (1 2) }

            headPos = 'object';
          }
        } // Store the list item and continue with parent


        if (!first) malformed = onError(current, 'has no list head');else items.unshift(first.object);
        current = parent && parent.subject;
      } // Don't remove any quads if the list is malformed


      if (malformed) remove = false; // Store the list under the value of its head
      else if (head) lists[head[headPos].value] = items;
    }); // Remove list quads if requested

    if (remove) this.removeQuads(toRemove);
    return lists;
  } // ### Store is an iterable.
  // Can be used where iterables are expected: for...of loops, array spread operator,
  // `yield*`, and destructuring assignment (order is not guaranteed).


  *[Symbol.iterator]() {
    yield* this.getQuads();
  }

} // Determines whether the argument is a string


exports.default = N3Store;

function isString(s) {
  return typeof s === 'string' || s instanceof String;
}
/**
 * A class that implements both DatasetCore and Readable.
 */


class DatasetCoreAndReadableStream extends _readableStream.Readable {
  constructor(n3Store, subject, predicate, object, graph) {
    super({
      objectMode: true
    });
    Object.assign(this, {
      n3Store,
      subject,
      predicate,
      object,
      graph
    });
  }

  get filtered() {
    if (!this._filtered) {
      const {
        n3Store,
        graph,
        object,
        predicate,
        subject
      } = this;
      const quads = n3Store.getQuads(subject, predicate, object, graph);
      this._filtered = new N3Store(quads, {
        factory: n3Store._factory
      });
    }

    return this._filtered;
  }

  get size() {
    return this.filtered.size;
  }

  _read() {
    for (const quad of this.filtered.getQuads()) this.push(quad);

    this.push(null);
  }

  add(quad) {
    return this.filtered.add(quad);
  }

  delete(quad) {
    return this.filtered.delete(quad);
  }

  has(quad) {
    return this.filtered.has(quad);
  }

  match(subject, predicate, object, graph) {
    return new DatasetCoreAndReadableStream(this.filtered, subject, predicate, object, graph);
  }

  *[Symbol.iterator]() {
    yield* this.filtered.getQuads();
  }

}

},{"./IRIs":125,"./N3DataFactory":126,"readable-stream":151}],130:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _N3Parser = _interopRequireDefault(require("./N3Parser"));

var _readableStream = require("readable-stream");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// **N3StreamParser** parses a text stream into a quad stream.
// ## Constructor
class N3StreamParser extends _readableStream.Transform {
  constructor(options) {
    super({
      decodeStrings: true
    });
    this._readableState.objectMode = true; // Set up parser with dummy stream to obtain `data` and `end` callbacks

    const parser = new _N3Parser.default(options);
    let onData, onEnd;
    parser.parse({
      on: (event, callback) => {
        switch (event) {
          case 'data':
            onData = callback;
            break;

          case 'end':
            onEnd = callback;
            break;
        }
      }
    }, // Handle quads by pushing them down the pipeline
    (error, quad) => {
      error && this.emit('error', error) || quad && this.push(quad);
    }, // Emit prefixes through the `prefix` event
    (prefix, uri) => {
      this.emit('prefix', prefix, uri);
    }); // Implement Transform methods through parser callbacks

    this._transform = (chunk, encoding, done) => {
      onData(chunk);
      done();
    };

    this._flush = done => {
      onEnd();
      done();
    };
  } // ### Parses a stream of strings


  import(stream) {
    stream.on('data', chunk => {
      this.write(chunk);
    });
    stream.on('end', () => {
      this.end();
    });
    stream.on('error', error => {
      this.emit('error', error);
    });
    return this;
  }

}

exports.default = N3StreamParser;

},{"./N3Parser":128,"readable-stream":151}],131:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _readableStream = require("readable-stream");

var _N3Writer = _interopRequireDefault(require("./N3Writer"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// **N3StreamWriter** serializes a quad stream into a text stream.
// ## Constructor
class N3StreamWriter extends _readableStream.Transform {
  constructor(options) {
    super({
      encoding: 'utf8',
      writableObjectMode: true
    }); // Set up writer with a dummy stream object

    const writer = this._writer = new _N3Writer.default({
      write: (quad, encoding, callback) => {
        this.push(quad);
        callback && callback();
      },
      end: callback => {
        this.push(null);
        callback && callback();
      }
    }, options); // Implement Transform methods on top of writer

    this._transform = (quad, encoding, done) => {
      writer.addQuad(quad, done);
    };

    this._flush = done => {
      writer.end(done);
    };
  } // ### Serializes a stream of quads


  import(stream) {
    stream.on('data', quad => {
      this.write(quad);
    });
    stream.on('end', () => {
      this.end();
    });
    stream.on('error', error => {
      this.emit('error', error);
    });
    stream.on('prefix', (prefix, iri) => {
      this._writer.addPrefix(prefix, iri);
    });
    return this;
  }

}

exports.default = N3StreamWriter;

},{"./N3Writer":133,"readable-stream":151}],132:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.inDefaultGraph = inDefaultGraph;
exports.isBlankNode = isBlankNode;
exports.isDefaultGraph = isDefaultGraph;
exports.isLiteral = isLiteral;
exports.isNamedNode = isNamedNode;
exports.isVariable = isVariable;
exports.prefix = prefix;
exports.prefixes = prefixes;

var _N3DataFactory = _interopRequireDefault(require("./N3DataFactory"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// **N3Util** provides N3 utility functions.
// Tests whether the given term represents an IRI
function isNamedNode(term) {
  return !!term && term.termType === 'NamedNode';
} // Tests whether the given term represents a blank node


function isBlankNode(term) {
  return !!term && term.termType === 'BlankNode';
} // Tests whether the given term represents a literal


function isLiteral(term) {
  return !!term && term.termType === 'Literal';
} // Tests whether the given term represents a variable


function isVariable(term) {
  return !!term && term.termType === 'Variable';
} // Tests whether the given term represents the default graph


function isDefaultGraph(term) {
  return !!term && term.termType === 'DefaultGraph';
} // Tests whether the given quad is in the default graph


function inDefaultGraph(quad) {
  return isDefaultGraph(quad.graph);
} // Creates a function that prepends the given IRI to a local name


function prefix(iri, factory) {
  return prefixes({
    '': iri
  }, factory)('');
} // Creates a function that allows registering and expanding prefixes


function prefixes(defaultPrefixes, factory) {
  // Add all of the default prefixes
  const prefixes = Object.create(null);

  for (const prefix in defaultPrefixes) processPrefix(prefix, defaultPrefixes[prefix]); // Set the default factory if none was specified


  factory = factory || _N3DataFactory.default; // Registers a new prefix (if an IRI was specified)
  // or retrieves a function that expands an existing prefix (if no IRI was specified)

  function processPrefix(prefix, iri) {
    // Create a new prefix if an IRI is specified or the prefix doesn't exist
    if (typeof iri === 'string') {
      // Create a function that expands the prefix
      const cache = Object.create(null);

      prefixes[prefix] = local => {
        return cache[local] || (cache[local] = factory.namedNode(iri + local));
      };
    } else if (!(prefix in prefixes)) {
      throw new Error(`Unknown prefix: ${prefix}`);
    }

    return prefixes[prefix];
  }

  return processPrefix;
}

},{"./N3DataFactory":126}],133:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _IRIs = _interopRequireDefault(require("./IRIs"));

var _N3DataFactory = _interopRequireWildcard(require("./N3DataFactory"));

var _N3Util = require("./N3Util");

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// **N3Writer** writes N3 documents.
const DEFAULTGRAPH = _N3DataFactory.default.defaultGraph();

const {
  rdf,
  xsd
} = _IRIs.default; // Characters in literals that require escaping

const escape = /["\\\t\n\r\b\f\u0000-\u0019\ud800-\udbff]/,
      escapeAll = /["\\\t\n\r\b\f\u0000-\u0019]|[\ud800-\udbff][\udc00-\udfff]/g,
      escapedCharacters = {
  '\\': '\\\\',
  '"': '\\"',
  '\t': '\\t',
  '\n': '\\n',
  '\r': '\\r',
  '\b': '\\b',
  '\f': '\\f'
}; // ## Placeholder class to represent already pretty-printed terms

class SerializedTerm extends _N3DataFactory.Term {
  // Pretty-printed nodes are not equal to any other node
  // (e.g., [] does not equal [])
  equals() {
    return false;
  }

} // ## Constructor


class N3Writer {
  constructor(outputStream, options) {
    // ### `_prefixRegex` matches a prefixed name or IRI that begins with one of the added prefixes
    this._prefixRegex = /$0^/; // Shift arguments if the first argument is not a stream

    if (outputStream && typeof outputStream.write !== 'function') options = outputStream, outputStream = null;
    options = options || {};
    this._lists = options.lists; // If no output stream given, send the output as string through the end callback

    if (!outputStream) {
      let output = '';
      this._outputStream = {
        write(chunk, encoding, done) {
          output += chunk;
          done && done();
        },

        end: done => {
          done && done(null, output);
        }
      };
      this._endStream = true;
    } else {
      this._outputStream = outputStream;
      this._endStream = options.end === undefined ? true : !!options.end;
    } // Initialize writer, depending on the format


    this._subject = null;

    if (!/triple|quad/i.test(options.format)) {
      this._lineMode = false;
      this._graph = DEFAULTGRAPH;
      this._prefixIRIs = Object.create(null);
      options.prefixes && this.addPrefixes(options.prefixes);

      if (options.baseIRI) {
        this._baseMatcher = new RegExp(`^${escapeRegex(options.baseIRI)}${options.baseIRI.endsWith('/') ? '' : '[#?]'}`);
        this._baseLength = options.baseIRI.length;
      }
    } else {
      this._lineMode = true;
      this._writeQuad = this._writeQuadLine;
    }
  } // ## Private methods
  // ### Whether the current graph is the default graph


  get _inDefaultGraph() {
    return DEFAULTGRAPH.equals(this._graph);
  } // ### `_write` writes the argument to the output stream


  _write(string, callback) {
    this._outputStream.write(string, 'utf8', callback);
  } // ### `_writeQuad` writes the quad to the output stream


  _writeQuad(subject, predicate, object, graph, done) {
    try {
      // Write the graph's label if it has changed
      if (!graph.equals(this._graph)) {
        // Close the previous graph and start the new one
        this._write((this._subject === null ? '' : this._inDefaultGraph ? '.\n' : '\n}\n') + (DEFAULTGRAPH.equals(graph) ? '' : `${this._encodeIriOrBlank(graph)} {\n`));

        this._graph = graph;
        this._subject = null;
      } // Don't repeat the subject if it's the same


      if (subject.equals(this._subject)) {
        // Don't repeat the predicate if it's the same
        if (predicate.equals(this._predicate)) this._write(`, ${this._encodeObject(object)}`, done); // Same subject, different predicate
        else this._write(`;\n    ${this._encodePredicate(this._predicate = predicate)} ${this._encodeObject(object)}`, done);
      } // Different subject; write the whole quad
      else this._write(`${(this._subject === null ? '' : '.\n') + this._encodeSubject(this._subject = subject)} ${this._encodePredicate(this._predicate = predicate)} ${this._encodeObject(object)}`, done);
    } catch (error) {
      done && done(error);
    }
  } // ### `_writeQuadLine` writes the quad to the output stream as a single line


  _writeQuadLine(subject, predicate, object, graph, done) {
    // Write the quad without prefixes
    delete this._prefixMatch;

    this._write(this.quadToString(subject, predicate, object, graph), done);
  } // ### `quadToString` serializes a quad as a string


  quadToString(subject, predicate, object, graph) {
    return `${this._encodeSubject(subject)} ${this._encodeIriOrBlank(predicate)} ${this._encodeObject(object)}${graph && graph.value ? ` ${this._encodeIriOrBlank(graph)} .\n` : ' .\n'}`;
  } // ### `quadsToString` serializes an array of quads as a string


  quadsToString(quads) {
    return quads.map(t => {
      return this.quadToString(t.subject, t.predicate, t.object, t.graph);
    }).join('');
  } // ### `_encodeSubject` represents a subject


  _encodeSubject(entity) {
    return entity.termType === 'Quad' ? this._encodeQuad(entity) : this._encodeIriOrBlank(entity);
  } // ### `_encodeIriOrBlank` represents an IRI or blank node


  _encodeIriOrBlank(entity) {
    // A blank node or list is represented as-is
    if (entity.termType !== 'NamedNode') {
      // If it is a list head, pretty-print it
      if (this._lists && entity.value in this._lists) entity = this.list(this._lists[entity.value]);
      return 'id' in entity ? entity.id : `_:${entity.value}`;
    }

    let iri = entity.value; // Use relative IRIs if requested and possible

    if (this._baseMatcher && this._baseMatcher.test(iri)) iri = iri.substr(this._baseLength); // Escape special characters

    if (escape.test(iri)) iri = iri.replace(escapeAll, characterReplacer); // Try to represent the IRI as prefixed name

    const prefixMatch = this._prefixRegex.exec(iri);

    return !prefixMatch ? `<${iri}>` : !prefixMatch[1] ? iri : this._prefixIRIs[prefixMatch[1]] + prefixMatch[2];
  } // ### `_encodeLiteral` represents a literal


  _encodeLiteral(literal) {
    // Escape special characters
    let value = literal.value;
    if (escape.test(value)) value = value.replace(escapeAll, characterReplacer); // Write a language-tagged literal

    if (literal.language) return `"${value}"@${literal.language}`; // Write dedicated literals per data type

    if (this._lineMode) {
      // Only abbreviate strings in N-Triples or N-Quads
      if (literal.datatype.value === xsd.string) return `"${value}"`;
    } else {
      // Use common datatype abbreviations in Turtle or TriG
      switch (literal.datatype.value) {
        case xsd.string:
          return `"${value}"`;

        case xsd.boolean:
          if (value === 'true' || value === 'false') return value;
          break;

        case xsd.integer:
          if (/^[+-]?\d+$/.test(value)) return value;
          break;

        case xsd.decimal:
          if (/^[+-]?\d*\.\d+$/.test(value)) return value;
          break;

        case xsd.double:
          if (/^[+-]?(?:\d+\.\d*|\.?\d+)[eE][+-]?\d+$/.test(value)) return value;
          break;
      }
    } // Write a regular datatyped literal


    return `"${value}"^^${this._encodeIriOrBlank(literal.datatype)}`;
  } // ### `_encodePredicate` represents a predicate


  _encodePredicate(predicate) {
    return predicate.value === rdf.type ? 'a' : this._encodeIriOrBlank(predicate);
  } // ### `_encodeObject` represents an object


  _encodeObject(object) {
    switch (object.termType) {
      case 'Quad':
        return this._encodeQuad(object);

      case 'Literal':
        return this._encodeLiteral(object);

      default:
        return this._encodeIriOrBlank(object);
    }
  } // ### `_encodeQuad` encodes an RDF* quad


  _encodeQuad({
    subject,
    predicate,
    object,
    graph
  }) {
    return `<<${this._encodeSubject(subject)} ${this._encodePredicate(predicate)} ${this._encodeObject(object)}${(0, _N3Util.isDefaultGraph)(graph) ? '' : ` ${this._encodeIriOrBlank(graph)}`}>>`;
  } // ### `_blockedWrite` replaces `_write` after the writer has been closed


  _blockedWrite() {
    throw new Error('Cannot write because the writer has been closed.');
  } // ### `addQuad` adds the quad to the output stream


  addQuad(subject, predicate, object, graph, done) {
    // The quad was given as an object, so shift parameters
    if (object === undefined) this._writeQuad(subject.subject, subject.predicate, subject.object, subject.graph, predicate); // The optional `graph` parameter was not provided
    else if (typeof graph === 'function') this._writeQuad(subject, predicate, object, DEFAULTGRAPH, graph); // The `graph` parameter was provided
    else this._writeQuad(subject, predicate, object, graph || DEFAULTGRAPH, done);
  } // ### `addQuads` adds the quads to the output stream


  addQuads(quads) {
    for (let i = 0; i < quads.length; i++) this.addQuad(quads[i]);
  } // ### `addPrefix` adds the prefix to the output stream


  addPrefix(prefix, iri, done) {
    const prefixes = {};
    prefixes[prefix] = iri;
    this.addPrefixes(prefixes, done);
  } // ### `addPrefixes` adds the prefixes to the output stream


  addPrefixes(prefixes, done) {
    // Ignore prefixes if not supported by the serialization
    if (!this._prefixIRIs) return done && done(); // Write all new prefixes

    let hasPrefixes = false;

    for (let prefix in prefixes) {
      let iri = prefixes[prefix];
      if (typeof iri !== 'string') iri = iri.value;
      hasPrefixes = true; // Finish a possible pending quad

      if (this._subject !== null) {
        this._write(this._inDefaultGraph ? '.\n' : '\n}\n');

        this._subject = null, this._graph = '';
      } // Store and write the prefix


      this._prefixIRIs[iri] = prefix += ':';

      this._write(`@prefix ${prefix} <${iri}>.\n`);
    } // Recreate the prefix matcher


    if (hasPrefixes) {
      let IRIlist = '',
          prefixList = '';

      for (const prefixIRI in this._prefixIRIs) {
        IRIlist += IRIlist ? `|${prefixIRI}` : prefixIRI;
        prefixList += (prefixList ? '|' : '') + this._prefixIRIs[prefixIRI];
      }

      IRIlist = escapeRegex(IRIlist, /[\]\/\(\)\*\+\?\.\\\$]/g, '\\$&');
      this._prefixRegex = new RegExp(`^(?:${prefixList})[^\/]*$|` + `^(${IRIlist})([a-zA-Z][\\-_a-zA-Z0-9]*)$`);
    } // End a prefix block with a newline


    this._write(hasPrefixes ? '\n' : '', done);
  } // ### `blank` creates a blank node with the given content


  blank(predicate, object) {
    let children = predicate,
        child,
        length; // Empty blank node

    if (predicate === undefined) children = []; // Blank node passed as blank(Term("predicate"), Term("object"))
    else if (predicate.termType) children = [{
      predicate: predicate,
      object: object
    }]; // Blank node passed as blank({ predicate: predicate, object: object })
    else if (!('length' in predicate)) children = [predicate];

    switch (length = children.length) {
      // Generate an empty blank node
      case 0:
        return new SerializedTerm('[]');
      // Generate a non-nested one-triple blank node

      case 1:
        child = children[0];
        if (!(child.object instanceof SerializedTerm)) return new SerializedTerm(`[ ${this._encodePredicate(child.predicate)} ${this._encodeObject(child.object)} ]`);
      // Generate a multi-triple or nested blank node

      default:
        let contents = '['; // Write all triples in order

        for (let i = 0; i < length; i++) {
          child = children[i]; // Write only the object is the predicate is the same as the previous

          if (child.predicate.equals(predicate)) contents += `, ${this._encodeObject(child.object)}`; // Otherwise, write the predicate and the object
          else {
            contents += `${(i ? ';\n  ' : '\n  ') + this._encodePredicate(child.predicate)} ${this._encodeObject(child.object)}`;
            predicate = child.predicate;
          }
        }

        return new SerializedTerm(`${contents}\n]`);
    }
  } // ### `list` creates a list node with the given content


  list(elements) {
    const length = elements && elements.length || 0,
          contents = new Array(length);

    for (let i = 0; i < length; i++) contents[i] = this._encodeObject(elements[i]);

    return new SerializedTerm(`(${contents.join(' ')})`);
  } // ### `end` signals the end of the output stream


  end(done) {
    // Finish a possible pending quad
    if (this._subject !== null) {
      this._write(this._inDefaultGraph ? '.\n' : '\n}\n');

      this._subject = null;
    } // Disallow further writing


    this._write = this._blockedWrite; // Try to end the underlying stream, ensuring done is called exactly one time

    let singleDone = done && ((error, result) => {
      singleDone = null, done(error, result);
    });

    if (this._endStream) {
      try {
        return this._outputStream.end(singleDone);
      } catch (error) {
        /* error closing stream */
      }
    }

    singleDone && singleDone();
  }

} // Replaces a character by its escaped version


exports.default = N3Writer;

function characterReplacer(character) {
  // Replace a single character by its escaped version
  let result = escapedCharacters[character];

  if (result === undefined) {
    // Replace a single character with its 4-bit unicode escape sequence
    if (character.length === 1) {
      result = character.charCodeAt(0).toString(16);
      result = '\\u0000'.substr(0, 6 - result.length) + result;
    } // Replace a surrogate pair with its 8-bit unicode escape sequence
    else {
      result = ((character.charCodeAt(0) - 0xD800) * 0x400 + character.charCodeAt(1) + 0x2400).toString(16);
      result = '\\U00000000'.substr(0, 10 - result.length) + result;
    }
  }

  return result;
}

function escapeRegex(regex) {
  return regex.replace(/[\]\/\(\)\*\+\?\.\\\$]/g, '\\$&');
}

},{"./IRIs":125,"./N3DataFactory":126,"./N3Util":132}],134:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
Object.defineProperty(exports, "BlankNode", {
  enumerable: true,
  get: function () {
    return _N3DataFactory.BlankNode;
  }
});
Object.defineProperty(exports, "DataFactory", {
  enumerable: true,
  get: function () {
    return _N3DataFactory.default;
  }
});
Object.defineProperty(exports, "DefaultGraph", {
  enumerable: true,
  get: function () {
    return _N3DataFactory.DefaultGraph;
  }
});
Object.defineProperty(exports, "Lexer", {
  enumerable: true,
  get: function () {
    return _N3Lexer.default;
  }
});
Object.defineProperty(exports, "Literal", {
  enumerable: true,
  get: function () {
    return _N3DataFactory.Literal;
  }
});
Object.defineProperty(exports, "NamedNode", {
  enumerable: true,
  get: function () {
    return _N3DataFactory.NamedNode;
  }
});
Object.defineProperty(exports, "Parser", {
  enumerable: true,
  get: function () {
    return _N3Parser.default;
  }
});
Object.defineProperty(exports, "Quad", {
  enumerable: true,
  get: function () {
    return _N3DataFactory.Quad;
  }
});
Object.defineProperty(exports, "Store", {
  enumerable: true,
  get: function () {
    return _N3Store.default;
  }
});
Object.defineProperty(exports, "StreamParser", {
  enumerable: true,
  get: function () {
    return _N3StreamParser.default;
  }
});
Object.defineProperty(exports, "StreamWriter", {
  enumerable: true,
  get: function () {
    return _N3StreamWriter.default;
  }
});
Object.defineProperty(exports, "Term", {
  enumerable: true,
  get: function () {
    return _N3DataFactory.Term;
  }
});
Object.defineProperty(exports, "Triple", {
  enumerable: true,
  get: function () {
    return _N3DataFactory.Triple;
  }
});
exports.Util = void 0;
Object.defineProperty(exports, "Variable", {
  enumerable: true,
  get: function () {
    return _N3DataFactory.Variable;
  }
});
Object.defineProperty(exports, "Writer", {
  enumerable: true,
  get: function () {
    return _N3Writer.default;
  }
});
Object.defineProperty(exports, "termFromId", {
  enumerable: true,
  get: function () {
    return _N3DataFactory.termFromId;
  }
});
Object.defineProperty(exports, "termToId", {
  enumerable: true,
  get: function () {
    return _N3DataFactory.termToId;
  }
});

var _N3Lexer = _interopRequireDefault(require("./N3Lexer"));

var _N3Parser = _interopRequireDefault(require("./N3Parser"));

var _N3Writer = _interopRequireDefault(require("./N3Writer"));

var _N3Store = _interopRequireDefault(require("./N3Store"));

var _N3StreamParser = _interopRequireDefault(require("./N3StreamParser"));

var _N3StreamWriter = _interopRequireDefault(require("./N3StreamWriter"));

var Util = _interopRequireWildcard(require("./N3Util"));

exports.Util = Util;

var _N3DataFactory = _interopRequireWildcard(require("./N3DataFactory"));

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

},{"./N3DataFactory":126,"./N3Lexer":127,"./N3Parser":128,"./N3Store":129,"./N3StreamParser":130,"./N3StreamWriter":131,"./N3Util":132,"./N3Writer":133}],135:[function(require,module,exports){
// shim for using process in browser
var process = module.exports = {};

// cached from whatever global is present so that test runners that stub it
// don't break things.  But we need to wrap it in a try catch in case it is
// wrapped in strict mode code which doesn't define any globals.  It's inside a
// function because try/catches deoptimize in certain engines.

var cachedSetTimeout;
var cachedClearTimeout;

function defaultSetTimout() {
    throw new Error('setTimeout has not been defined');
}
function defaultClearTimeout () {
    throw new Error('clearTimeout has not been defined');
}
(function () {
    try {
        if (typeof setTimeout === 'function') {
            cachedSetTimeout = setTimeout;
        } else {
            cachedSetTimeout = defaultSetTimout;
        }
    } catch (e) {
        cachedSetTimeout = defaultSetTimout;
    }
    try {
        if (typeof clearTimeout === 'function') {
            cachedClearTimeout = clearTimeout;
        } else {
            cachedClearTimeout = defaultClearTimeout;
        }
    } catch (e) {
        cachedClearTimeout = defaultClearTimeout;
    }
} ())
function runTimeout(fun) {
    if (cachedSetTimeout === setTimeout) {
        //normal enviroments in sane situations
        return setTimeout(fun, 0);
    }
    // if setTimeout wasn't available but was latter defined
    if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
        cachedSetTimeout = setTimeout;
        return setTimeout(fun, 0);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedSetTimeout(fun, 0);
    } catch(e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't trust the global object when called normally
            return cachedSetTimeout.call(null, fun, 0);
        } catch(e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error
            return cachedSetTimeout.call(this, fun, 0);
        }
    }


}
function runClearTimeout(marker) {
    if (cachedClearTimeout === clearTimeout) {
        //normal enviroments in sane situations
        return clearTimeout(marker);
    }
    // if clearTimeout wasn't available but was latter defined
    if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
        cachedClearTimeout = clearTimeout;
        return clearTimeout(marker);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedClearTimeout(marker);
    } catch (e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't  trust the global object when called normally
            return cachedClearTimeout.call(null, marker);
        } catch (e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error.
            // Some versions of I.E. have different rules for clearTimeout vs setTimeout
            return cachedClearTimeout.call(this, marker);
        }
    }



}
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = runTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    runClearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        runTimeout(drainQueue);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;
process.prependListener = noop;
process.prependOnceListener = noop;

process.listeners = function (name) { return [] }

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}],136:[function(require,module,exports){
(function (global){(function (){
/*! queue-microtask. MIT License. Feross Aboukhadijeh <https://feross.org/opensource> */
let promise

module.exports = typeof queueMicrotask === 'function'
  ? queueMicrotask.bind(typeof window !== 'undefined' ? window : global)
  // reuse resolved promise, and allocate it lazily
  : cb => (promise || (promise = Promise.resolve()))
    .then(cb)
    .catch(err => setTimeout(() => { throw err }, 0))

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],137:[function(require,module,exports){
'use strict';

function _inheritsLoose(subClass, superClass) { subClass.prototype = Object.create(superClass.prototype); subClass.prototype.constructor = subClass; subClass.__proto__ = superClass; }

var codes = {};

function createErrorType(code, message, Base) {
  if (!Base) {
    Base = Error;
  }

  function getMessage(arg1, arg2, arg3) {
    if (typeof message === 'string') {
      return message;
    } else {
      return message(arg1, arg2, arg3);
    }
  }

  var NodeError =
  /*#__PURE__*/
  function (_Base) {
    _inheritsLoose(NodeError, _Base);

    function NodeError(arg1, arg2, arg3) {
      return _Base.call(this, getMessage(arg1, arg2, arg3)) || this;
    }

    return NodeError;
  }(Base);

  NodeError.prototype.name = Base.name;
  NodeError.prototype.code = code;
  codes[code] = NodeError;
} // https://github.com/nodejs/node/blob/v10.8.0/lib/internal/errors.js


function oneOf(expected, thing) {
  if (Array.isArray(expected)) {
    var len = expected.length;
    expected = expected.map(function (i) {
      return String(i);
    });

    if (len > 2) {
      return "one of ".concat(thing, " ").concat(expected.slice(0, len - 1).join(', '), ", or ") + expected[len - 1];
    } else if (len === 2) {
      return "one of ".concat(thing, " ").concat(expected[0], " or ").concat(expected[1]);
    } else {
      return "of ".concat(thing, " ").concat(expected[0]);
    }
  } else {
    return "of ".concat(thing, " ").concat(String(expected));
  }
} // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/startsWith


function startsWith(str, search, pos) {
  return str.substr(!pos || pos < 0 ? 0 : +pos, search.length) === search;
} // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/endsWith


function endsWith(str, search, this_len) {
  if (this_len === undefined || this_len > str.length) {
    this_len = str.length;
  }

  return str.substring(this_len - search.length, this_len) === search;
} // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/includes


function includes(str, search, start) {
  if (typeof start !== 'number') {
    start = 0;
  }

  if (start + search.length > str.length) {
    return false;
  } else {
    return str.indexOf(search, start) !== -1;
  }
}

createErrorType('ERR_INVALID_OPT_VALUE', function (name, value) {
  return 'The value "' + value + '" is invalid for option "' + name + '"';
}, TypeError);
createErrorType('ERR_INVALID_ARG_TYPE', function (name, expected, actual) {
  // determiner: 'must be' or 'must not be'
  var determiner;

  if (typeof expected === 'string' && startsWith(expected, 'not ')) {
    determiner = 'must not be';
    expected = expected.replace(/^not /, '');
  } else {
    determiner = 'must be';
  }

  var msg;

  if (endsWith(name, ' argument')) {
    // For cases like 'first argument'
    msg = "The ".concat(name, " ").concat(determiner, " ").concat(oneOf(expected, 'type'));
  } else {
    var type = includes(name, '.') ? 'property' : 'argument';
    msg = "The \"".concat(name, "\" ").concat(type, " ").concat(determiner, " ").concat(oneOf(expected, 'type'));
  }

  msg += ". Received type ".concat(typeof actual);
  return msg;
}, TypeError);
createErrorType('ERR_STREAM_PUSH_AFTER_EOF', 'stream.push() after EOF');
createErrorType('ERR_METHOD_NOT_IMPLEMENTED', function (name) {
  return 'The ' + name + ' method is not implemented';
});
createErrorType('ERR_STREAM_PREMATURE_CLOSE', 'Premature close');
createErrorType('ERR_STREAM_DESTROYED', function (name) {
  return 'Cannot call ' + name + ' after a stream was destroyed';
});
createErrorType('ERR_MULTIPLE_CALLBACK', 'Callback called multiple times');
createErrorType('ERR_STREAM_CANNOT_PIPE', 'Cannot pipe, not readable');
createErrorType('ERR_STREAM_WRITE_AFTER_END', 'write after end');
createErrorType('ERR_STREAM_NULL_VALUES', 'May not write null values to stream', TypeError);
createErrorType('ERR_UNKNOWN_ENCODING', function (arg) {
  return 'Unknown encoding: ' + arg;
}, TypeError);
createErrorType('ERR_STREAM_UNSHIFT_AFTER_END_EVENT', 'stream.unshift() after end event');
module.exports.codes = codes;

},{}],138:[function(require,module,exports){
(function (process){(function (){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
// a duplex stream is just a stream that is both readable and writable.
// Since JS doesn't have multiple prototypal inheritance, this class
// prototypally inherits from Readable, and then parasitically from
// Writable.
'use strict';
/*<replacement>*/

var objectKeys = Object.keys || function (obj) {
  var keys = [];

  for (var key in obj) {
    keys.push(key);
  }

  return keys;
};
/*</replacement>*/


module.exports = Duplex;

var Readable = require('./_stream_readable');

var Writable = require('./_stream_writable');

require('inherits')(Duplex, Readable);

{
  // Allow the keys array to be GC'ed.
  var keys = objectKeys(Writable.prototype);

  for (var v = 0; v < keys.length; v++) {
    var method = keys[v];
    if (!Duplex.prototype[method]) Duplex.prototype[method] = Writable.prototype[method];
  }
}

function Duplex(options) {
  if (!(this instanceof Duplex)) return new Duplex(options);
  Readable.call(this, options);
  Writable.call(this, options);
  this.allowHalfOpen = true;

  if (options) {
    if (options.readable === false) this.readable = false;
    if (options.writable === false) this.writable = false;

    if (options.allowHalfOpen === false) {
      this.allowHalfOpen = false;
      this.once('end', onend);
    }
  }
}

Object.defineProperty(Duplex.prototype, 'writableHighWaterMark', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState.highWaterMark;
  }
});
Object.defineProperty(Duplex.prototype, 'writableBuffer', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState && this._writableState.getBuffer();
  }
});
Object.defineProperty(Duplex.prototype, 'writableLength', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState.length;
  }
}); // the no-half-open enforcer

function onend() {
  // If the writable side ended, then we're ok.
  if (this._writableState.ended) return; // no more data can be written.
  // But allow more writes to happen in this tick.

  process.nextTick(onEndNT, this);
}

function onEndNT(self) {
  self.end();
}

Object.defineProperty(Duplex.prototype, 'destroyed', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    if (this._readableState === undefined || this._writableState === undefined) {
      return false;
    }

    return this._readableState.destroyed && this._writableState.destroyed;
  },
  set: function set(value) {
    // we ignore the value if the stream
    // has not been initialized yet
    if (this._readableState === undefined || this._writableState === undefined) {
      return;
    } // backward compatibility, the user is explicitly
    // managing destroyed


    this._readableState.destroyed = value;
    this._writableState.destroyed = value;
  }
});
}).call(this)}).call(this,require('_process'))
},{"./_stream_readable":140,"./_stream_writable":142,"_process":135,"inherits":49}],139:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
// a passthrough stream.
// basically just the most minimal sort of Transform stream.
// Every written chunk gets output as-is.
'use strict';

module.exports = PassThrough;

var Transform = require('./_stream_transform');

require('inherits')(PassThrough, Transform);

function PassThrough(options) {
  if (!(this instanceof PassThrough)) return new PassThrough(options);
  Transform.call(this, options);
}

PassThrough.prototype._transform = function (chunk, encoding, cb) {
  cb(null, chunk);
};
},{"./_stream_transform":141,"inherits":49}],140:[function(require,module,exports){
(function (process,global){(function (){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
'use strict';

module.exports = Readable;
/*<replacement>*/

var Duplex;
/*</replacement>*/

Readable.ReadableState = ReadableState;
/*<replacement>*/

var EE = require('events').EventEmitter;

var EElistenerCount = function EElistenerCount(emitter, type) {
  return emitter.listeners(type).length;
};
/*</replacement>*/

/*<replacement>*/


var Stream = require('./internal/streams/stream');
/*</replacement>*/


var Buffer = require('buffer').Buffer;

var OurUint8Array = global.Uint8Array || function () {};

function _uint8ArrayToBuffer(chunk) {
  return Buffer.from(chunk);
}

function _isUint8Array(obj) {
  return Buffer.isBuffer(obj) || obj instanceof OurUint8Array;
}
/*<replacement>*/


var debugUtil = require('util');

var debug;

if (debugUtil && debugUtil.debuglog) {
  debug = debugUtil.debuglog('stream');
} else {
  debug = function debug() {};
}
/*</replacement>*/


var BufferList = require('./internal/streams/buffer_list');

var destroyImpl = require('./internal/streams/destroy');

var _require = require('./internal/streams/state'),
    getHighWaterMark = _require.getHighWaterMark;

var _require$codes = require('../errors').codes,
    ERR_INVALID_ARG_TYPE = _require$codes.ERR_INVALID_ARG_TYPE,
    ERR_STREAM_PUSH_AFTER_EOF = _require$codes.ERR_STREAM_PUSH_AFTER_EOF,
    ERR_METHOD_NOT_IMPLEMENTED = _require$codes.ERR_METHOD_NOT_IMPLEMENTED,
    ERR_STREAM_UNSHIFT_AFTER_END_EVENT = _require$codes.ERR_STREAM_UNSHIFT_AFTER_END_EVENT; // Lazy loaded to improve the startup performance.


var StringDecoder;
var createReadableStreamAsyncIterator;
var from;

require('inherits')(Readable, Stream);

var errorOrDestroy = destroyImpl.errorOrDestroy;
var kProxyEvents = ['error', 'close', 'destroy', 'pause', 'resume'];

function prependListener(emitter, event, fn) {
  // Sadly this is not cacheable as some libraries bundle their own
  // event emitter implementation with them.
  if (typeof emitter.prependListener === 'function') return emitter.prependListener(event, fn); // This is a hack to make sure that our error handler is attached before any
  // userland ones.  NEVER DO THIS. This is here only because this code needs
  // to continue to work with older versions of Node.js that do not include
  // the prependListener() method. The goal is to eventually remove this hack.

  if (!emitter._events || !emitter._events[event]) emitter.on(event, fn);else if (Array.isArray(emitter._events[event])) emitter._events[event].unshift(fn);else emitter._events[event] = [fn, emitter._events[event]];
}

function ReadableState(options, stream, isDuplex) {
  Duplex = Duplex || require('./_stream_duplex');
  options = options || {}; // Duplex streams are both readable and writable, but share
  // the same options object.
  // However, some cases require setting options to different
  // values for the readable and the writable sides of the duplex stream.
  // These options can be provided separately as readableXXX and writableXXX.

  if (typeof isDuplex !== 'boolean') isDuplex = stream instanceof Duplex; // object stream flag. Used to make read(n) ignore n and to
  // make all the buffer merging and length checks go away

  this.objectMode = !!options.objectMode;
  if (isDuplex) this.objectMode = this.objectMode || !!options.readableObjectMode; // the point at which it stops calling _read() to fill the buffer
  // Note: 0 is a valid value, means "don't call _read preemptively ever"

  this.highWaterMark = getHighWaterMark(this, options, 'readableHighWaterMark', isDuplex); // A linked list is used to store data chunks instead of an array because the
  // linked list can remove elements from the beginning faster than
  // array.shift()

  this.buffer = new BufferList();
  this.length = 0;
  this.pipes = null;
  this.pipesCount = 0;
  this.flowing = null;
  this.ended = false;
  this.endEmitted = false;
  this.reading = false; // a flag to be able to tell if the event 'readable'/'data' is emitted
  // immediately, or on a later tick.  We set this to true at first, because
  // any actions that shouldn't happen until "later" should generally also
  // not happen before the first read call.

  this.sync = true; // whenever we return null, then we set a flag to say
  // that we're awaiting a 'readable' event emission.

  this.needReadable = false;
  this.emittedReadable = false;
  this.readableListening = false;
  this.resumeScheduled = false;
  this.paused = true; // Should close be emitted on destroy. Defaults to true.

  this.emitClose = options.emitClose !== false; // Should .destroy() be called after 'end' (and potentially 'finish')

  this.autoDestroy = !!options.autoDestroy; // has it been destroyed

  this.destroyed = false; // Crypto is kind of old and crusty.  Historically, its default string
  // encoding is 'binary' so we have to make this configurable.
  // Everything else in the universe uses 'utf8', though.

  this.defaultEncoding = options.defaultEncoding || 'utf8'; // the number of writers that are awaiting a drain event in .pipe()s

  this.awaitDrain = 0; // if true, a maybeReadMore has been scheduled

  this.readingMore = false;
  this.decoder = null;
  this.encoding = null;

  if (options.encoding) {
    if (!StringDecoder) StringDecoder = require('string_decoder/').StringDecoder;
    this.decoder = new StringDecoder(options.encoding);
    this.encoding = options.encoding;
  }
}

function Readable(options) {
  Duplex = Duplex || require('./_stream_duplex');
  if (!(this instanceof Readable)) return new Readable(options); // Checking for a Stream.Duplex instance is faster here instead of inside
  // the ReadableState constructor, at least with V8 6.5

  var isDuplex = this instanceof Duplex;
  this._readableState = new ReadableState(options, this, isDuplex); // legacy

  this.readable = true;

  if (options) {
    if (typeof options.read === 'function') this._read = options.read;
    if (typeof options.destroy === 'function') this._destroy = options.destroy;
  }

  Stream.call(this);
}

Object.defineProperty(Readable.prototype, 'destroyed', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    if (this._readableState === undefined) {
      return false;
    }

    return this._readableState.destroyed;
  },
  set: function set(value) {
    // we ignore the value if the stream
    // has not been initialized yet
    if (!this._readableState) {
      return;
    } // backward compatibility, the user is explicitly
    // managing destroyed


    this._readableState.destroyed = value;
  }
});
Readable.prototype.destroy = destroyImpl.destroy;
Readable.prototype._undestroy = destroyImpl.undestroy;

Readable.prototype._destroy = function (err, cb) {
  cb(err);
}; // Manually shove something into the read() buffer.
// This returns true if the highWaterMark has not been hit yet,
// similar to how Writable.write() returns true if you should
// write() some more.


Readable.prototype.push = function (chunk, encoding) {
  var state = this._readableState;
  var skipChunkCheck;

  if (!state.objectMode) {
    if (typeof chunk === 'string') {
      encoding = encoding || state.defaultEncoding;

      if (encoding !== state.encoding) {
        chunk = Buffer.from(chunk, encoding);
        encoding = '';
      }

      skipChunkCheck = true;
    }
  } else {
    skipChunkCheck = true;
  }

  return readableAddChunk(this, chunk, encoding, false, skipChunkCheck);
}; // Unshift should *always* be something directly out of read()


Readable.prototype.unshift = function (chunk) {
  return readableAddChunk(this, chunk, null, true, false);
};

function readableAddChunk(stream, chunk, encoding, addToFront, skipChunkCheck) {
  debug('readableAddChunk', chunk);
  var state = stream._readableState;

  if (chunk === null) {
    state.reading = false;
    onEofChunk(stream, state);
  } else {
    var er;
    if (!skipChunkCheck) er = chunkInvalid(state, chunk);

    if (er) {
      errorOrDestroy(stream, er);
    } else if (state.objectMode || chunk && chunk.length > 0) {
      if (typeof chunk !== 'string' && !state.objectMode && Object.getPrototypeOf(chunk) !== Buffer.prototype) {
        chunk = _uint8ArrayToBuffer(chunk);
      }

      if (addToFront) {
        if (state.endEmitted) errorOrDestroy(stream, new ERR_STREAM_UNSHIFT_AFTER_END_EVENT());else addChunk(stream, state, chunk, true);
      } else if (state.ended) {
        errorOrDestroy(stream, new ERR_STREAM_PUSH_AFTER_EOF());
      } else if (state.destroyed) {
        return false;
      } else {
        state.reading = false;

        if (state.decoder && !encoding) {
          chunk = state.decoder.write(chunk);
          if (state.objectMode || chunk.length !== 0) addChunk(stream, state, chunk, false);else maybeReadMore(stream, state);
        } else {
          addChunk(stream, state, chunk, false);
        }
      }
    } else if (!addToFront) {
      state.reading = false;
      maybeReadMore(stream, state);
    }
  } // We can push more data if we are below the highWaterMark.
  // Also, if we have no data yet, we can stand some more bytes.
  // This is to work around cases where hwm=0, such as the repl.


  return !state.ended && (state.length < state.highWaterMark || state.length === 0);
}

function addChunk(stream, state, chunk, addToFront) {
  if (state.flowing && state.length === 0 && !state.sync) {
    state.awaitDrain = 0;
    stream.emit('data', chunk);
  } else {
    // update the buffer info.
    state.length += state.objectMode ? 1 : chunk.length;
    if (addToFront) state.buffer.unshift(chunk);else state.buffer.push(chunk);
    if (state.needReadable) emitReadable(stream);
  }

  maybeReadMore(stream, state);
}

function chunkInvalid(state, chunk) {
  var er;

  if (!_isUint8Array(chunk) && typeof chunk !== 'string' && chunk !== undefined && !state.objectMode) {
    er = new ERR_INVALID_ARG_TYPE('chunk', ['string', 'Buffer', 'Uint8Array'], chunk);
  }

  return er;
}

Readable.prototype.isPaused = function () {
  return this._readableState.flowing === false;
}; // backwards compatibility.


Readable.prototype.setEncoding = function (enc) {
  if (!StringDecoder) StringDecoder = require('string_decoder/').StringDecoder;
  var decoder = new StringDecoder(enc);
  this._readableState.decoder = decoder; // If setEncoding(null), decoder.encoding equals utf8

  this._readableState.encoding = this._readableState.decoder.encoding; // Iterate over current buffer to convert already stored Buffers:

  var p = this._readableState.buffer.head;
  var content = '';

  while (p !== null) {
    content += decoder.write(p.data);
    p = p.next;
  }

  this._readableState.buffer.clear();

  if (content !== '') this._readableState.buffer.push(content);
  this._readableState.length = content.length;
  return this;
}; // Don't raise the hwm > 1GB


var MAX_HWM = 0x40000000;

function computeNewHighWaterMark(n) {
  if (n >= MAX_HWM) {
    // TODO(ronag): Throw ERR_VALUE_OUT_OF_RANGE.
    n = MAX_HWM;
  } else {
    // Get the next highest power of 2 to prevent increasing hwm excessively in
    // tiny amounts
    n--;
    n |= n >>> 1;
    n |= n >>> 2;
    n |= n >>> 4;
    n |= n >>> 8;
    n |= n >>> 16;
    n++;
  }

  return n;
} // This function is designed to be inlinable, so please take care when making
// changes to the function body.


function howMuchToRead(n, state) {
  if (n <= 0 || state.length === 0 && state.ended) return 0;
  if (state.objectMode) return 1;

  if (n !== n) {
    // Only flow one buffer at a time
    if (state.flowing && state.length) return state.buffer.head.data.length;else return state.length;
  } // If we're asking for more than the current hwm, then raise the hwm.


  if (n > state.highWaterMark) state.highWaterMark = computeNewHighWaterMark(n);
  if (n <= state.length) return n; // Don't have enough

  if (!state.ended) {
    state.needReadable = true;
    return 0;
  }

  return state.length;
} // you can override either this method, or the async _read(n) below.


Readable.prototype.read = function (n) {
  debug('read', n);
  n = parseInt(n, 10);
  var state = this._readableState;
  var nOrig = n;
  if (n !== 0) state.emittedReadable = false; // if we're doing read(0) to trigger a readable event, but we
  // already have a bunch of data in the buffer, then just trigger
  // the 'readable' event and move on.

  if (n === 0 && state.needReadable && ((state.highWaterMark !== 0 ? state.length >= state.highWaterMark : state.length > 0) || state.ended)) {
    debug('read: emitReadable', state.length, state.ended);
    if (state.length === 0 && state.ended) endReadable(this);else emitReadable(this);
    return null;
  }

  n = howMuchToRead(n, state); // if we've ended, and we're now clear, then finish it up.

  if (n === 0 && state.ended) {
    if (state.length === 0) endReadable(this);
    return null;
  } // All the actual chunk generation logic needs to be
  // *below* the call to _read.  The reason is that in certain
  // synthetic stream cases, such as passthrough streams, _read
  // may be a completely synchronous operation which may change
  // the state of the read buffer, providing enough data when
  // before there was *not* enough.
  //
  // So, the steps are:
  // 1. Figure out what the state of things will be after we do
  // a read from the buffer.
  //
  // 2. If that resulting state will trigger a _read, then call _read.
  // Note that this may be asynchronous, or synchronous.  Yes, it is
  // deeply ugly to write APIs this way, but that still doesn't mean
  // that the Readable class should behave improperly, as streams are
  // designed to be sync/async agnostic.
  // Take note if the _read call is sync or async (ie, if the read call
  // has returned yet), so that we know whether or not it's safe to emit
  // 'readable' etc.
  //
  // 3. Actually pull the requested chunks out of the buffer and return.
  // if we need a readable event, then we need to do some reading.


  var doRead = state.needReadable;
  debug('need readable', doRead); // if we currently have less than the highWaterMark, then also read some

  if (state.length === 0 || state.length - n < state.highWaterMark) {
    doRead = true;
    debug('length less than watermark', doRead);
  } // however, if we've ended, then there's no point, and if we're already
  // reading, then it's unnecessary.


  if (state.ended || state.reading) {
    doRead = false;
    debug('reading or ended', doRead);
  } else if (doRead) {
    debug('do read');
    state.reading = true;
    state.sync = true; // if the length is currently zero, then we *need* a readable event.

    if (state.length === 0) state.needReadable = true; // call internal read method

    this._read(state.highWaterMark);

    state.sync = false; // If _read pushed data synchronously, then `reading` will be false,
    // and we need to re-evaluate how much data we can return to the user.

    if (!state.reading) n = howMuchToRead(nOrig, state);
  }

  var ret;
  if (n > 0) ret = fromList(n, state);else ret = null;

  if (ret === null) {
    state.needReadable = state.length <= state.highWaterMark;
    n = 0;
  } else {
    state.length -= n;
    state.awaitDrain = 0;
  }

  if (state.length === 0) {
    // If we have nothing in the buffer, then we want to know
    // as soon as we *do* get something into the buffer.
    if (!state.ended) state.needReadable = true; // If we tried to read() past the EOF, then emit end on the next tick.

    if (nOrig !== n && state.ended) endReadable(this);
  }

  if (ret !== null) this.emit('data', ret);
  return ret;
};

function onEofChunk(stream, state) {
  debug('onEofChunk');
  if (state.ended) return;

  if (state.decoder) {
    var chunk = state.decoder.end();

    if (chunk && chunk.length) {
      state.buffer.push(chunk);
      state.length += state.objectMode ? 1 : chunk.length;
    }
  }

  state.ended = true;

  if (state.sync) {
    // if we are sync, wait until next tick to emit the data.
    // Otherwise we risk emitting data in the flow()
    // the readable code triggers during a read() call
    emitReadable(stream);
  } else {
    // emit 'readable' now to make sure it gets picked up.
    state.needReadable = false;

    if (!state.emittedReadable) {
      state.emittedReadable = true;
      emitReadable_(stream);
    }
  }
} // Don't emit readable right away in sync mode, because this can trigger
// another read() call => stack overflow.  This way, it might trigger
// a nextTick recursion warning, but that's not so bad.


function emitReadable(stream) {
  var state = stream._readableState;
  debug('emitReadable', state.needReadable, state.emittedReadable);
  state.needReadable = false;

  if (!state.emittedReadable) {
    debug('emitReadable', state.flowing);
    state.emittedReadable = true;
    process.nextTick(emitReadable_, stream);
  }
}

function emitReadable_(stream) {
  var state = stream._readableState;
  debug('emitReadable_', state.destroyed, state.length, state.ended);

  if (!state.destroyed && (state.length || state.ended)) {
    stream.emit('readable');
    state.emittedReadable = false;
  } // The stream needs another readable event if
  // 1. It is not flowing, as the flow mechanism will take
  //    care of it.
  // 2. It is not ended.
  // 3. It is below the highWaterMark, so we can schedule
  //    another readable later.


  state.needReadable = !state.flowing && !state.ended && state.length <= state.highWaterMark;
  flow(stream);
} // at this point, the user has presumably seen the 'readable' event,
// and called read() to consume some data.  that may have triggered
// in turn another _read(n) call, in which case reading = true if
// it's in progress.
// However, if we're not ended, or reading, and the length < hwm,
// then go ahead and try to read some more preemptively.


function maybeReadMore(stream, state) {
  if (!state.readingMore) {
    state.readingMore = true;
    process.nextTick(maybeReadMore_, stream, state);
  }
}

function maybeReadMore_(stream, state) {
  // Attempt to read more data if we should.
  //
  // The conditions for reading more data are (one of):
  // - Not enough data buffered (state.length < state.highWaterMark). The loop
  //   is responsible for filling the buffer with enough data if such data
  //   is available. If highWaterMark is 0 and we are not in the flowing mode
  //   we should _not_ attempt to buffer any extra data. We'll get more data
  //   when the stream consumer calls read() instead.
  // - No data in the buffer, and the stream is in flowing mode. In this mode
  //   the loop below is responsible for ensuring read() is called. Failing to
  //   call read here would abort the flow and there's no other mechanism for
  //   continuing the flow if the stream consumer has just subscribed to the
  //   'data' event.
  //
  // In addition to the above conditions to keep reading data, the following
  // conditions prevent the data from being read:
  // - The stream has ended (state.ended).
  // - There is already a pending 'read' operation (state.reading). This is a
  //   case where the the stream has called the implementation defined _read()
  //   method, but they are processing the call asynchronously and have _not_
  //   called push() with new data. In this case we skip performing more
  //   read()s. The execution ends in this method again after the _read() ends
  //   up calling push() with more data.
  while (!state.reading && !state.ended && (state.length < state.highWaterMark || state.flowing && state.length === 0)) {
    var len = state.length;
    debug('maybeReadMore read 0');
    stream.read(0);
    if (len === state.length) // didn't get any data, stop spinning.
      break;
  }

  state.readingMore = false;
} // abstract method.  to be overridden in specific implementation classes.
// call cb(er, data) where data is <= n in length.
// for virtual (non-string, non-buffer) streams, "length" is somewhat
// arbitrary, and perhaps not very meaningful.


Readable.prototype._read = function (n) {
  errorOrDestroy(this, new ERR_METHOD_NOT_IMPLEMENTED('_read()'));
};

Readable.prototype.pipe = function (dest, pipeOpts) {
  var src = this;
  var state = this._readableState;

  switch (state.pipesCount) {
    case 0:
      state.pipes = dest;
      break;

    case 1:
      state.pipes = [state.pipes, dest];
      break;

    default:
      state.pipes.push(dest);
      break;
  }

  state.pipesCount += 1;
  debug('pipe count=%d opts=%j', state.pipesCount, pipeOpts);
  var doEnd = (!pipeOpts || pipeOpts.end !== false) && dest !== process.stdout && dest !== process.stderr;
  var endFn = doEnd ? onend : unpipe;
  if (state.endEmitted) process.nextTick(endFn);else src.once('end', endFn);
  dest.on('unpipe', onunpipe);

  function onunpipe(readable, unpipeInfo) {
    debug('onunpipe');

    if (readable === src) {
      if (unpipeInfo && unpipeInfo.hasUnpiped === false) {
        unpipeInfo.hasUnpiped = true;
        cleanup();
      }
    }
  }

  function onend() {
    debug('onend');
    dest.end();
  } // when the dest drains, it reduces the awaitDrain counter
  // on the source.  This would be more elegant with a .once()
  // handler in flow(), but adding and removing repeatedly is
  // too slow.


  var ondrain = pipeOnDrain(src);
  dest.on('drain', ondrain);
  var cleanedUp = false;

  function cleanup() {
    debug('cleanup'); // cleanup event handlers once the pipe is broken

    dest.removeListener('close', onclose);
    dest.removeListener('finish', onfinish);
    dest.removeListener('drain', ondrain);
    dest.removeListener('error', onerror);
    dest.removeListener('unpipe', onunpipe);
    src.removeListener('end', onend);
    src.removeListener('end', unpipe);
    src.removeListener('data', ondata);
    cleanedUp = true; // if the reader is waiting for a drain event from this
    // specific writer, then it would cause it to never start
    // flowing again.
    // So, if this is awaiting a drain, then we just call it now.
    // If we don't know, then assume that we are waiting for one.

    if (state.awaitDrain && (!dest._writableState || dest._writableState.needDrain)) ondrain();
  }

  src.on('data', ondata);

  function ondata(chunk) {
    debug('ondata');
    var ret = dest.write(chunk);
    debug('dest.write', ret);

    if (ret === false) {
      // If the user unpiped during `dest.write()`, it is possible
      // to get stuck in a permanently paused state if that write
      // also returned false.
      // => Check whether `dest` is still a piping destination.
      if ((state.pipesCount === 1 && state.pipes === dest || state.pipesCount > 1 && indexOf(state.pipes, dest) !== -1) && !cleanedUp) {
        debug('false write response, pause', state.awaitDrain);
        state.awaitDrain++;
      }

      src.pause();
    }
  } // if the dest has an error, then stop piping into it.
  // however, don't suppress the throwing behavior for this.


  function onerror(er) {
    debug('onerror', er);
    unpipe();
    dest.removeListener('error', onerror);
    if (EElistenerCount(dest, 'error') === 0) errorOrDestroy(dest, er);
  } // Make sure our error handler is attached before userland ones.


  prependListener(dest, 'error', onerror); // Both close and finish should trigger unpipe, but only once.

  function onclose() {
    dest.removeListener('finish', onfinish);
    unpipe();
  }

  dest.once('close', onclose);

  function onfinish() {
    debug('onfinish');
    dest.removeListener('close', onclose);
    unpipe();
  }

  dest.once('finish', onfinish);

  function unpipe() {
    debug('unpipe');
    src.unpipe(dest);
  } // tell the dest that it's being piped to


  dest.emit('pipe', src); // start the flow if it hasn't been started already.

  if (!state.flowing) {
    debug('pipe resume');
    src.resume();
  }

  return dest;
};

function pipeOnDrain(src) {
  return function pipeOnDrainFunctionResult() {
    var state = src._readableState;
    debug('pipeOnDrain', state.awaitDrain);
    if (state.awaitDrain) state.awaitDrain--;

    if (state.awaitDrain === 0 && EElistenerCount(src, 'data')) {
      state.flowing = true;
      flow(src);
    }
  };
}

Readable.prototype.unpipe = function (dest) {
  var state = this._readableState;
  var unpipeInfo = {
    hasUnpiped: false
  }; // if we're not piping anywhere, then do nothing.

  if (state.pipesCount === 0) return this; // just one destination.  most common case.

  if (state.pipesCount === 1) {
    // passed in one, but it's not the right one.
    if (dest && dest !== state.pipes) return this;
    if (!dest) dest = state.pipes; // got a match.

    state.pipes = null;
    state.pipesCount = 0;
    state.flowing = false;
    if (dest) dest.emit('unpipe', this, unpipeInfo);
    return this;
  } // slow case. multiple pipe destinations.


  if (!dest) {
    // remove all.
    var dests = state.pipes;
    var len = state.pipesCount;
    state.pipes = null;
    state.pipesCount = 0;
    state.flowing = false;

    for (var i = 0; i < len; i++) {
      dests[i].emit('unpipe', this, {
        hasUnpiped: false
      });
    }

    return this;
  } // try to find the right one.


  var index = indexOf(state.pipes, dest);
  if (index === -1) return this;
  state.pipes.splice(index, 1);
  state.pipesCount -= 1;
  if (state.pipesCount === 1) state.pipes = state.pipes[0];
  dest.emit('unpipe', this, unpipeInfo);
  return this;
}; // set up data events if they are asked for
// Ensure readable listeners eventually get something


Readable.prototype.on = function (ev, fn) {
  var res = Stream.prototype.on.call(this, ev, fn);
  var state = this._readableState;

  if (ev === 'data') {
    // update readableListening so that resume() may be a no-op
    // a few lines down. This is needed to support once('readable').
    state.readableListening = this.listenerCount('readable') > 0; // Try start flowing on next tick if stream isn't explicitly paused

    if (state.flowing !== false) this.resume();
  } else if (ev === 'readable') {
    if (!state.endEmitted && !state.readableListening) {
      state.readableListening = state.needReadable = true;
      state.flowing = false;
      state.emittedReadable = false;
      debug('on readable', state.length, state.reading);

      if (state.length) {
        emitReadable(this);
      } else if (!state.reading) {
        process.nextTick(nReadingNextTick, this);
      }
    }
  }

  return res;
};

Readable.prototype.addListener = Readable.prototype.on;

Readable.prototype.removeListener = function (ev, fn) {
  var res = Stream.prototype.removeListener.call(this, ev, fn);

  if (ev === 'readable') {
    // We need to check if there is someone still listening to
    // readable and reset the state. However this needs to happen
    // after readable has been emitted but before I/O (nextTick) to
    // support once('readable', fn) cycles. This means that calling
    // resume within the same tick will have no
    // effect.
    process.nextTick(updateReadableListening, this);
  }

  return res;
};

Readable.prototype.removeAllListeners = function (ev) {
  var res = Stream.prototype.removeAllListeners.apply(this, arguments);

  if (ev === 'readable' || ev === undefined) {
    // We need to check if there is someone still listening to
    // readable and reset the state. However this needs to happen
    // after readable has been emitted but before I/O (nextTick) to
    // support once('readable', fn) cycles. This means that calling
    // resume within the same tick will have no
    // effect.
    process.nextTick(updateReadableListening, this);
  }

  return res;
};

function updateReadableListening(self) {
  var state = self._readableState;
  state.readableListening = self.listenerCount('readable') > 0;

  if (state.resumeScheduled && !state.paused) {
    // flowing needs to be set to true now, otherwise
    // the upcoming resume will not flow.
    state.flowing = true; // crude way to check if we should resume
  } else if (self.listenerCount('data') > 0) {
    self.resume();
  }
}

function nReadingNextTick(self) {
  debug('readable nexttick read 0');
  self.read(0);
} // pause() and resume() are remnants of the legacy readable stream API
// If the user uses them, then switch into old mode.


Readable.prototype.resume = function () {
  var state = this._readableState;

  if (!state.flowing) {
    debug('resume'); // we flow only if there is no one listening
    // for readable, but we still have to call
    // resume()

    state.flowing = !state.readableListening;
    resume(this, state);
  }

  state.paused = false;
  return this;
};

function resume(stream, state) {
  if (!state.resumeScheduled) {
    state.resumeScheduled = true;
    process.nextTick(resume_, stream, state);
  }
}

function resume_(stream, state) {
  debug('resume', state.reading);

  if (!state.reading) {
    stream.read(0);
  }

  state.resumeScheduled = false;
  stream.emit('resume');
  flow(stream);
  if (state.flowing && !state.reading) stream.read(0);
}

Readable.prototype.pause = function () {
  debug('call pause flowing=%j', this._readableState.flowing);

  if (this._readableState.flowing !== false) {
    debug('pause');
    this._readableState.flowing = false;
    this.emit('pause');
  }

  this._readableState.paused = true;
  return this;
};

function flow(stream) {
  var state = stream._readableState;
  debug('flow', state.flowing);

  while (state.flowing && stream.read() !== null) {
    ;
  }
} // wrap an old-style stream as the async data source.
// This is *not* part of the readable stream interface.
// It is an ugly unfortunate mess of history.


Readable.prototype.wrap = function (stream) {
  var _this = this;

  var state = this._readableState;
  var paused = false;
  stream.on('end', function () {
    debug('wrapped end');

    if (state.decoder && !state.ended) {
      var chunk = state.decoder.end();
      if (chunk && chunk.length) _this.push(chunk);
    }

    _this.push(null);
  });
  stream.on('data', function (chunk) {
    debug('wrapped data');
    if (state.decoder) chunk = state.decoder.write(chunk); // don't skip over falsy values in objectMode

    if (state.objectMode && (chunk === null || chunk === undefined)) return;else if (!state.objectMode && (!chunk || !chunk.length)) return;

    var ret = _this.push(chunk);

    if (!ret) {
      paused = true;
      stream.pause();
    }
  }); // proxy all the other methods.
  // important when wrapping filters and duplexes.

  for (var i in stream) {
    if (this[i] === undefined && typeof stream[i] === 'function') {
      this[i] = function methodWrap(method) {
        return function methodWrapReturnFunction() {
          return stream[method].apply(stream, arguments);
        };
      }(i);
    }
  } // proxy certain important events.


  for (var n = 0; n < kProxyEvents.length; n++) {
    stream.on(kProxyEvents[n], this.emit.bind(this, kProxyEvents[n]));
  } // when we try to consume some more bytes, simply unpause the
  // underlying stream.


  this._read = function (n) {
    debug('wrapped _read', n);

    if (paused) {
      paused = false;
      stream.resume();
    }
  };

  return this;
};

if (typeof Symbol === 'function') {
  Readable.prototype[Symbol.asyncIterator] = function () {
    if (createReadableStreamAsyncIterator === undefined) {
      createReadableStreamAsyncIterator = require('./internal/streams/async_iterator');
    }

    return createReadableStreamAsyncIterator(this);
  };
}

Object.defineProperty(Readable.prototype, 'readableHighWaterMark', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._readableState.highWaterMark;
  }
});
Object.defineProperty(Readable.prototype, 'readableBuffer', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._readableState && this._readableState.buffer;
  }
});
Object.defineProperty(Readable.prototype, 'readableFlowing', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._readableState.flowing;
  },
  set: function set(state) {
    if (this._readableState) {
      this._readableState.flowing = state;
    }
  }
}); // exposed for testing purposes only.

Readable._fromList = fromList;
Object.defineProperty(Readable.prototype, 'readableLength', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._readableState.length;
  }
}); // Pluck off n bytes from an array of buffers.
// Length is the combined lengths of all the buffers in the list.
// This function is designed to be inlinable, so please take care when making
// changes to the function body.

function fromList(n, state) {
  // nothing buffered
  if (state.length === 0) return null;
  var ret;
  if (state.objectMode) ret = state.buffer.shift();else if (!n || n >= state.length) {
    // read it all, truncate the list
    if (state.decoder) ret = state.buffer.join('');else if (state.buffer.length === 1) ret = state.buffer.first();else ret = state.buffer.concat(state.length);
    state.buffer.clear();
  } else {
    // read part of list
    ret = state.buffer.consume(n, state.decoder);
  }
  return ret;
}

function endReadable(stream) {
  var state = stream._readableState;
  debug('endReadable', state.endEmitted);

  if (!state.endEmitted) {
    state.ended = true;
    process.nextTick(endReadableNT, state, stream);
  }
}

function endReadableNT(state, stream) {
  debug('endReadableNT', state.endEmitted, state.length); // Check that we didn't get one last unshift.

  if (!state.endEmitted && state.length === 0) {
    state.endEmitted = true;
    stream.readable = false;
    stream.emit('end');

    if (state.autoDestroy) {
      // In case of duplex streams we need a way to detect
      // if the writable side is ready for autoDestroy as well
      var wState = stream._writableState;

      if (!wState || wState.autoDestroy && wState.finished) {
        stream.destroy();
      }
    }
  }
}

if (typeof Symbol === 'function') {
  Readable.from = function (iterable, opts) {
    if (from === undefined) {
      from = require('./internal/streams/from');
    }

    return from(Readable, iterable, opts);
  };
}

function indexOf(xs, x) {
  for (var i = 0, l = xs.length; i < l; i++) {
    if (xs[i] === x) return i;
  }

  return -1;
}
}).call(this)}).call(this,require('_process'),typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"../errors":137,"./_stream_duplex":138,"./internal/streams/async_iterator":143,"./internal/streams/buffer_list":144,"./internal/streams/destroy":145,"./internal/streams/from":147,"./internal/streams/state":149,"./internal/streams/stream":150,"_process":135,"buffer":44,"events":46,"inherits":49,"string_decoder/":153,"util":43}],141:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
// a transform stream is a readable/writable stream where you do
// something with the data.  Sometimes it's called a "filter",
// but that's not a great name for it, since that implies a thing where
// some bits pass through, and others are simply ignored.  (That would
// be a valid example of a transform, of course.)
//
// While the output is causally related to the input, it's not a
// necessarily symmetric or synchronous transformation.  For example,
// a zlib stream might take multiple plain-text writes(), and then
// emit a single compressed chunk some time in the future.
//
// Here's how this works:
//
// The Transform stream has all the aspects of the readable and writable
// stream classes.  When you write(chunk), that calls _write(chunk,cb)
// internally, and returns false if there's a lot of pending writes
// buffered up.  When you call read(), that calls _read(n) until
// there's enough pending readable data buffered up.
//
// In a transform stream, the written data is placed in a buffer.  When
// _read(n) is called, it transforms the queued up data, calling the
// buffered _write cb's as it consumes chunks.  If consuming a single
// written chunk would result in multiple output chunks, then the first
// outputted bit calls the readcb, and subsequent chunks just go into
// the read buffer, and will cause it to emit 'readable' if necessary.
//
// This way, back-pressure is actually determined by the reading side,
// since _read has to be called to start processing a new chunk.  However,
// a pathological inflate type of transform can cause excessive buffering
// here.  For example, imagine a stream where every byte of input is
// interpreted as an integer from 0-255, and then results in that many
// bytes of output.  Writing the 4 bytes {ff,ff,ff,ff} would result in
// 1kb of data being output.  In this case, you could write a very small
// amount of input, and end up with a very large amount of output.  In
// such a pathological inflating mechanism, there'd be no way to tell
// the system to stop doing the transform.  A single 4MB write could
// cause the system to run out of memory.
//
// However, even in such a pathological case, only a single written chunk
// would be consumed, and then the rest would wait (un-transformed) until
// the results of the previous transformed chunk were consumed.
'use strict';

module.exports = Transform;

var _require$codes = require('../errors').codes,
    ERR_METHOD_NOT_IMPLEMENTED = _require$codes.ERR_METHOD_NOT_IMPLEMENTED,
    ERR_MULTIPLE_CALLBACK = _require$codes.ERR_MULTIPLE_CALLBACK,
    ERR_TRANSFORM_ALREADY_TRANSFORMING = _require$codes.ERR_TRANSFORM_ALREADY_TRANSFORMING,
    ERR_TRANSFORM_WITH_LENGTH_0 = _require$codes.ERR_TRANSFORM_WITH_LENGTH_0;

var Duplex = require('./_stream_duplex');

require('inherits')(Transform, Duplex);

function afterTransform(er, data) {
  var ts = this._transformState;
  ts.transforming = false;
  var cb = ts.writecb;

  if (cb === null) {
    return this.emit('error', new ERR_MULTIPLE_CALLBACK());
  }

  ts.writechunk = null;
  ts.writecb = null;
  if (data != null) // single equals check for both `null` and `undefined`
    this.push(data);
  cb(er);
  var rs = this._readableState;
  rs.reading = false;

  if (rs.needReadable || rs.length < rs.highWaterMark) {
    this._read(rs.highWaterMark);
  }
}

function Transform(options) {
  if (!(this instanceof Transform)) return new Transform(options);
  Duplex.call(this, options);
  this._transformState = {
    afterTransform: afterTransform.bind(this),
    needTransform: false,
    transforming: false,
    writecb: null,
    writechunk: null,
    writeencoding: null
  }; // start out asking for a readable event once data is transformed.

  this._readableState.needReadable = true; // we have implemented the _read method, and done the other things
  // that Readable wants before the first _read call, so unset the
  // sync guard flag.

  this._readableState.sync = false;

  if (options) {
    if (typeof options.transform === 'function') this._transform = options.transform;
    if (typeof options.flush === 'function') this._flush = options.flush;
  } // When the writable side finishes, then flush out anything remaining.


  this.on('prefinish', prefinish);
}

function prefinish() {
  var _this = this;

  if (typeof this._flush === 'function' && !this._readableState.destroyed) {
    this._flush(function (er, data) {
      done(_this, er, data);
    });
  } else {
    done(this, null, null);
  }
}

Transform.prototype.push = function (chunk, encoding) {
  this._transformState.needTransform = false;
  return Duplex.prototype.push.call(this, chunk, encoding);
}; // This is the part where you do stuff!
// override this function in implementation classes.
// 'chunk' is an input chunk.
//
// Call `push(newChunk)` to pass along transformed output
// to the readable side.  You may call 'push' zero or more times.
//
// Call `cb(err)` when you are done with this chunk.  If you pass
// an error, then that'll put the hurt on the whole operation.  If you
// never call cb(), then you'll never get another chunk.


Transform.prototype._transform = function (chunk, encoding, cb) {
  cb(new ERR_METHOD_NOT_IMPLEMENTED('_transform()'));
};

Transform.prototype._write = function (chunk, encoding, cb) {
  var ts = this._transformState;
  ts.writecb = cb;
  ts.writechunk = chunk;
  ts.writeencoding = encoding;

  if (!ts.transforming) {
    var rs = this._readableState;
    if (ts.needTransform || rs.needReadable || rs.length < rs.highWaterMark) this._read(rs.highWaterMark);
  }
}; // Doesn't matter what the args are here.
// _transform does all the work.
// That we got here means that the readable side wants more data.


Transform.prototype._read = function (n) {
  var ts = this._transformState;

  if (ts.writechunk !== null && !ts.transforming) {
    ts.transforming = true;

    this._transform(ts.writechunk, ts.writeencoding, ts.afterTransform);
  } else {
    // mark that we need a transform, so that any data that comes in
    // will get processed, now that we've asked for it.
    ts.needTransform = true;
  }
};

Transform.prototype._destroy = function (err, cb) {
  Duplex.prototype._destroy.call(this, err, function (err2) {
    cb(err2);
  });
};

function done(stream, er, data) {
  if (er) return stream.emit('error', er);
  if (data != null) // single equals check for both `null` and `undefined`
    stream.push(data); // TODO(BridgeAR): Write a test for these two error cases
  // if there's nothing in the write buffer, then that means
  // that nothing more will ever be provided

  if (stream._writableState.length) throw new ERR_TRANSFORM_WITH_LENGTH_0();
  if (stream._transformState.transforming) throw new ERR_TRANSFORM_ALREADY_TRANSFORMING();
  return stream.push(null);
}
},{"../errors":137,"./_stream_duplex":138,"inherits":49}],142:[function(require,module,exports){
(function (process,global){(function (){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
// A bit simpler than readable streams.
// Implement an async ._write(chunk, encoding, cb), and it'll handle all
// the drain event emission and buffering.
'use strict';

module.exports = Writable;
/* <replacement> */

function WriteReq(chunk, encoding, cb) {
  this.chunk = chunk;
  this.encoding = encoding;
  this.callback = cb;
  this.next = null;
} // It seems a linked list but it is not
// there will be only 2 of these for each stream


function CorkedRequest(state) {
  var _this = this;

  this.next = null;
  this.entry = null;

  this.finish = function () {
    onCorkedFinish(_this, state);
  };
}
/* </replacement> */

/*<replacement>*/


var Duplex;
/*</replacement>*/

Writable.WritableState = WritableState;
/*<replacement>*/

var internalUtil = {
  deprecate: require('util-deprecate')
};
/*</replacement>*/

/*<replacement>*/

var Stream = require('./internal/streams/stream');
/*</replacement>*/


var Buffer = require('buffer').Buffer;

var OurUint8Array = global.Uint8Array || function () {};

function _uint8ArrayToBuffer(chunk) {
  return Buffer.from(chunk);
}

function _isUint8Array(obj) {
  return Buffer.isBuffer(obj) || obj instanceof OurUint8Array;
}

var destroyImpl = require('./internal/streams/destroy');

var _require = require('./internal/streams/state'),
    getHighWaterMark = _require.getHighWaterMark;

var _require$codes = require('../errors').codes,
    ERR_INVALID_ARG_TYPE = _require$codes.ERR_INVALID_ARG_TYPE,
    ERR_METHOD_NOT_IMPLEMENTED = _require$codes.ERR_METHOD_NOT_IMPLEMENTED,
    ERR_MULTIPLE_CALLBACK = _require$codes.ERR_MULTIPLE_CALLBACK,
    ERR_STREAM_CANNOT_PIPE = _require$codes.ERR_STREAM_CANNOT_PIPE,
    ERR_STREAM_DESTROYED = _require$codes.ERR_STREAM_DESTROYED,
    ERR_STREAM_NULL_VALUES = _require$codes.ERR_STREAM_NULL_VALUES,
    ERR_STREAM_WRITE_AFTER_END = _require$codes.ERR_STREAM_WRITE_AFTER_END,
    ERR_UNKNOWN_ENCODING = _require$codes.ERR_UNKNOWN_ENCODING;

var errorOrDestroy = destroyImpl.errorOrDestroy;

require('inherits')(Writable, Stream);

function nop() {}

function WritableState(options, stream, isDuplex) {
  Duplex = Duplex || require('./_stream_duplex');
  options = options || {}; // Duplex streams are both readable and writable, but share
  // the same options object.
  // However, some cases require setting options to different
  // values for the readable and the writable sides of the duplex stream,
  // e.g. options.readableObjectMode vs. options.writableObjectMode, etc.

  if (typeof isDuplex !== 'boolean') isDuplex = stream instanceof Duplex; // object stream flag to indicate whether or not this stream
  // contains buffers or objects.

  this.objectMode = !!options.objectMode;
  if (isDuplex) this.objectMode = this.objectMode || !!options.writableObjectMode; // the point at which write() starts returning false
  // Note: 0 is a valid value, means that we always return false if
  // the entire buffer is not flushed immediately on write()

  this.highWaterMark = getHighWaterMark(this, options, 'writableHighWaterMark', isDuplex); // if _final has been called

  this.finalCalled = false; // drain event flag.

  this.needDrain = false; // at the start of calling end()

  this.ending = false; // when end() has been called, and returned

  this.ended = false; // when 'finish' is emitted

  this.finished = false; // has it been destroyed

  this.destroyed = false; // should we decode strings into buffers before passing to _write?
  // this is here so that some node-core streams can optimize string
  // handling at a lower level.

  var noDecode = options.decodeStrings === false;
  this.decodeStrings = !noDecode; // Crypto is kind of old and crusty.  Historically, its default string
  // encoding is 'binary' so we have to make this configurable.
  // Everything else in the universe uses 'utf8', though.

  this.defaultEncoding = options.defaultEncoding || 'utf8'; // not an actual buffer we keep track of, but a measurement
  // of how much we're waiting to get pushed to some underlying
  // socket or file.

  this.length = 0; // a flag to see when we're in the middle of a write.

  this.writing = false; // when true all writes will be buffered until .uncork() call

  this.corked = 0; // a flag to be able to tell if the onwrite cb is called immediately,
  // or on a later tick.  We set this to true at first, because any
  // actions that shouldn't happen until "later" should generally also
  // not happen before the first write call.

  this.sync = true; // a flag to know if we're processing previously buffered items, which
  // may call the _write() callback in the same tick, so that we don't
  // end up in an overlapped onwrite situation.

  this.bufferProcessing = false; // the callback that's passed to _write(chunk,cb)

  this.onwrite = function (er) {
    onwrite(stream, er);
  }; // the callback that the user supplies to write(chunk,encoding,cb)


  this.writecb = null; // the amount that is being written when _write is called.

  this.writelen = 0;
  this.bufferedRequest = null;
  this.lastBufferedRequest = null; // number of pending user-supplied write callbacks
  // this must be 0 before 'finish' can be emitted

  this.pendingcb = 0; // emit prefinish if the only thing we're waiting for is _write cbs
  // This is relevant for synchronous Transform streams

  this.prefinished = false; // True if the error was already emitted and should not be thrown again

  this.errorEmitted = false; // Should close be emitted on destroy. Defaults to true.

  this.emitClose = options.emitClose !== false; // Should .destroy() be called after 'finish' (and potentially 'end')

  this.autoDestroy = !!options.autoDestroy; // count buffered requests

  this.bufferedRequestCount = 0; // allocate the first CorkedRequest, there is always
  // one allocated and free to use, and we maintain at most two

  this.corkedRequestsFree = new CorkedRequest(this);
}

WritableState.prototype.getBuffer = function getBuffer() {
  var current = this.bufferedRequest;
  var out = [];

  while (current) {
    out.push(current);
    current = current.next;
  }

  return out;
};

(function () {
  try {
    Object.defineProperty(WritableState.prototype, 'buffer', {
      get: internalUtil.deprecate(function writableStateBufferGetter() {
        return this.getBuffer();
      }, '_writableState.buffer is deprecated. Use _writableState.getBuffer ' + 'instead.', 'DEP0003')
    });
  } catch (_) {}
})(); // Test _writableState for inheritance to account for Duplex streams,
// whose prototype chain only points to Readable.


var realHasInstance;

if (typeof Symbol === 'function' && Symbol.hasInstance && typeof Function.prototype[Symbol.hasInstance] === 'function') {
  realHasInstance = Function.prototype[Symbol.hasInstance];
  Object.defineProperty(Writable, Symbol.hasInstance, {
    value: function value(object) {
      if (realHasInstance.call(this, object)) return true;
      if (this !== Writable) return false;
      return object && object._writableState instanceof WritableState;
    }
  });
} else {
  realHasInstance = function realHasInstance(object) {
    return object instanceof this;
  };
}

function Writable(options) {
  Duplex = Duplex || require('./_stream_duplex'); // Writable ctor is applied to Duplexes, too.
  // `realHasInstance` is necessary because using plain `instanceof`
  // would return false, as no `_writableState` property is attached.
  // Trying to use the custom `instanceof` for Writable here will also break the
  // Node.js LazyTransform implementation, which has a non-trivial getter for
  // `_writableState` that would lead to infinite recursion.
  // Checking for a Stream.Duplex instance is faster here instead of inside
  // the WritableState constructor, at least with V8 6.5

  var isDuplex = this instanceof Duplex;
  if (!isDuplex && !realHasInstance.call(Writable, this)) return new Writable(options);
  this._writableState = new WritableState(options, this, isDuplex); // legacy.

  this.writable = true;

  if (options) {
    if (typeof options.write === 'function') this._write = options.write;
    if (typeof options.writev === 'function') this._writev = options.writev;
    if (typeof options.destroy === 'function') this._destroy = options.destroy;
    if (typeof options.final === 'function') this._final = options.final;
  }

  Stream.call(this);
} // Otherwise people can pipe Writable streams, which is just wrong.


Writable.prototype.pipe = function () {
  errorOrDestroy(this, new ERR_STREAM_CANNOT_PIPE());
};

function writeAfterEnd(stream, cb) {
  var er = new ERR_STREAM_WRITE_AFTER_END(); // TODO: defer error events consistently everywhere, not just the cb

  errorOrDestroy(stream, er);
  process.nextTick(cb, er);
} // Checks that a user-supplied chunk is valid, especially for the particular
// mode the stream is in. Currently this means that `null` is never accepted
// and undefined/non-string values are only allowed in object mode.


function validChunk(stream, state, chunk, cb) {
  var er;

  if (chunk === null) {
    er = new ERR_STREAM_NULL_VALUES();
  } else if (typeof chunk !== 'string' && !state.objectMode) {
    er = new ERR_INVALID_ARG_TYPE('chunk', ['string', 'Buffer'], chunk);
  }

  if (er) {
    errorOrDestroy(stream, er);
    process.nextTick(cb, er);
    return false;
  }

  return true;
}

Writable.prototype.write = function (chunk, encoding, cb) {
  var state = this._writableState;
  var ret = false;

  var isBuf = !state.objectMode && _isUint8Array(chunk);

  if (isBuf && !Buffer.isBuffer(chunk)) {
    chunk = _uint8ArrayToBuffer(chunk);
  }

  if (typeof encoding === 'function') {
    cb = encoding;
    encoding = null;
  }

  if (isBuf) encoding = 'buffer';else if (!encoding) encoding = state.defaultEncoding;
  if (typeof cb !== 'function') cb = nop;
  if (state.ending) writeAfterEnd(this, cb);else if (isBuf || validChunk(this, state, chunk, cb)) {
    state.pendingcb++;
    ret = writeOrBuffer(this, state, isBuf, chunk, encoding, cb);
  }
  return ret;
};

Writable.prototype.cork = function () {
  this._writableState.corked++;
};

Writable.prototype.uncork = function () {
  var state = this._writableState;

  if (state.corked) {
    state.corked--;
    if (!state.writing && !state.corked && !state.bufferProcessing && state.bufferedRequest) clearBuffer(this, state);
  }
};

Writable.prototype.setDefaultEncoding = function setDefaultEncoding(encoding) {
  // node::ParseEncoding() requires lower case.
  if (typeof encoding === 'string') encoding = encoding.toLowerCase();
  if (!(['hex', 'utf8', 'utf-8', 'ascii', 'binary', 'base64', 'ucs2', 'ucs-2', 'utf16le', 'utf-16le', 'raw'].indexOf((encoding + '').toLowerCase()) > -1)) throw new ERR_UNKNOWN_ENCODING(encoding);
  this._writableState.defaultEncoding = encoding;
  return this;
};

Object.defineProperty(Writable.prototype, 'writableBuffer', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState && this._writableState.getBuffer();
  }
});

function decodeChunk(state, chunk, encoding) {
  if (!state.objectMode && state.decodeStrings !== false && typeof chunk === 'string') {
    chunk = Buffer.from(chunk, encoding);
  }

  return chunk;
}

Object.defineProperty(Writable.prototype, 'writableHighWaterMark', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState.highWaterMark;
  }
}); // if we're already writing something, then just put this
// in the queue, and wait our turn.  Otherwise, call _write
// If we return false, then we need a drain event, so set that flag.

function writeOrBuffer(stream, state, isBuf, chunk, encoding, cb) {
  if (!isBuf) {
    var newChunk = decodeChunk(state, chunk, encoding);

    if (chunk !== newChunk) {
      isBuf = true;
      encoding = 'buffer';
      chunk = newChunk;
    }
  }

  var len = state.objectMode ? 1 : chunk.length;
  state.length += len;
  var ret = state.length < state.highWaterMark; // we must ensure that previous needDrain will not be reset to false.

  if (!ret) state.needDrain = true;

  if (state.writing || state.corked) {
    var last = state.lastBufferedRequest;
    state.lastBufferedRequest = {
      chunk: chunk,
      encoding: encoding,
      isBuf: isBuf,
      callback: cb,
      next: null
    };

    if (last) {
      last.next = state.lastBufferedRequest;
    } else {
      state.bufferedRequest = state.lastBufferedRequest;
    }

    state.bufferedRequestCount += 1;
  } else {
    doWrite(stream, state, false, len, chunk, encoding, cb);
  }

  return ret;
}

function doWrite(stream, state, writev, len, chunk, encoding, cb) {
  state.writelen = len;
  state.writecb = cb;
  state.writing = true;
  state.sync = true;
  if (state.destroyed) state.onwrite(new ERR_STREAM_DESTROYED('write'));else if (writev) stream._writev(chunk, state.onwrite);else stream._write(chunk, encoding, state.onwrite);
  state.sync = false;
}

function onwriteError(stream, state, sync, er, cb) {
  --state.pendingcb;

  if (sync) {
    // defer the callback if we are being called synchronously
    // to avoid piling up things on the stack
    process.nextTick(cb, er); // this can emit finish, and it will always happen
    // after error

    process.nextTick(finishMaybe, stream, state);
    stream._writableState.errorEmitted = true;
    errorOrDestroy(stream, er);
  } else {
    // the caller expect this to happen before if
    // it is async
    cb(er);
    stream._writableState.errorEmitted = true;
    errorOrDestroy(stream, er); // this can emit finish, but finish must
    // always follow error

    finishMaybe(stream, state);
  }
}

function onwriteStateUpdate(state) {
  state.writing = false;
  state.writecb = null;
  state.length -= state.writelen;
  state.writelen = 0;
}

function onwrite(stream, er) {
  var state = stream._writableState;
  var sync = state.sync;
  var cb = state.writecb;
  if (typeof cb !== 'function') throw new ERR_MULTIPLE_CALLBACK();
  onwriteStateUpdate(state);
  if (er) onwriteError(stream, state, sync, er, cb);else {
    // Check if we're actually ready to finish, but don't emit yet
    var finished = needFinish(state) || stream.destroyed;

    if (!finished && !state.corked && !state.bufferProcessing && state.bufferedRequest) {
      clearBuffer(stream, state);
    }

    if (sync) {
      process.nextTick(afterWrite, stream, state, finished, cb);
    } else {
      afterWrite(stream, state, finished, cb);
    }
  }
}

function afterWrite(stream, state, finished, cb) {
  if (!finished) onwriteDrain(stream, state);
  state.pendingcb--;
  cb();
  finishMaybe(stream, state);
} // Must force callback to be called on nextTick, so that we don't
// emit 'drain' before the write() consumer gets the 'false' return
// value, and has a chance to attach a 'drain' listener.


function onwriteDrain(stream, state) {
  if (state.length === 0 && state.needDrain) {
    state.needDrain = false;
    stream.emit('drain');
  }
} // if there's something in the buffer waiting, then process it


function clearBuffer(stream, state) {
  state.bufferProcessing = true;
  var entry = state.bufferedRequest;

  if (stream._writev && entry && entry.next) {
    // Fast case, write everything using _writev()
    var l = state.bufferedRequestCount;
    var buffer = new Array(l);
    var holder = state.corkedRequestsFree;
    holder.entry = entry;
    var count = 0;
    var allBuffers = true;

    while (entry) {
      buffer[count] = entry;
      if (!entry.isBuf) allBuffers = false;
      entry = entry.next;
      count += 1;
    }

    buffer.allBuffers = allBuffers;
    doWrite(stream, state, true, state.length, buffer, '', holder.finish); // doWrite is almost always async, defer these to save a bit of time
    // as the hot path ends with doWrite

    state.pendingcb++;
    state.lastBufferedRequest = null;

    if (holder.next) {
      state.corkedRequestsFree = holder.next;
      holder.next = null;
    } else {
      state.corkedRequestsFree = new CorkedRequest(state);
    }

    state.bufferedRequestCount = 0;
  } else {
    // Slow case, write chunks one-by-one
    while (entry) {
      var chunk = entry.chunk;
      var encoding = entry.encoding;
      var cb = entry.callback;
      var len = state.objectMode ? 1 : chunk.length;
      doWrite(stream, state, false, len, chunk, encoding, cb);
      entry = entry.next;
      state.bufferedRequestCount--; // if we didn't call the onwrite immediately, then
      // it means that we need to wait until it does.
      // also, that means that the chunk and cb are currently
      // being processed, so move the buffer counter past them.

      if (state.writing) {
        break;
      }
    }

    if (entry === null) state.lastBufferedRequest = null;
  }

  state.bufferedRequest = entry;
  state.bufferProcessing = false;
}

Writable.prototype._write = function (chunk, encoding, cb) {
  cb(new ERR_METHOD_NOT_IMPLEMENTED('_write()'));
};

Writable.prototype._writev = null;

Writable.prototype.end = function (chunk, encoding, cb) {
  var state = this._writableState;

  if (typeof chunk === 'function') {
    cb = chunk;
    chunk = null;
    encoding = null;
  } else if (typeof encoding === 'function') {
    cb = encoding;
    encoding = null;
  }

  if (chunk !== null && chunk !== undefined) this.write(chunk, encoding); // .end() fully uncorks

  if (state.corked) {
    state.corked = 1;
    this.uncork();
  } // ignore unnecessary end() calls.


  if (!state.ending) endWritable(this, state, cb);
  return this;
};

Object.defineProperty(Writable.prototype, 'writableLength', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState.length;
  }
});

function needFinish(state) {
  return state.ending && state.length === 0 && state.bufferedRequest === null && !state.finished && !state.writing;
}

function callFinal(stream, state) {
  stream._final(function (err) {
    state.pendingcb--;

    if (err) {
      errorOrDestroy(stream, err);
    }

    state.prefinished = true;
    stream.emit('prefinish');
    finishMaybe(stream, state);
  });
}

function prefinish(stream, state) {
  if (!state.prefinished && !state.finalCalled) {
    if (typeof stream._final === 'function' && !state.destroyed) {
      state.pendingcb++;
      state.finalCalled = true;
      process.nextTick(callFinal, stream, state);
    } else {
      state.prefinished = true;
      stream.emit('prefinish');
    }
  }
}

function finishMaybe(stream, state) {
  var need = needFinish(state);

  if (need) {
    prefinish(stream, state);

    if (state.pendingcb === 0) {
      state.finished = true;
      stream.emit('finish');

      if (state.autoDestroy) {
        // In case of duplex streams we need a way to detect
        // if the readable side is ready for autoDestroy as well
        var rState = stream._readableState;

        if (!rState || rState.autoDestroy && rState.endEmitted) {
          stream.destroy();
        }
      }
    }
  }

  return need;
}

function endWritable(stream, state, cb) {
  state.ending = true;
  finishMaybe(stream, state);

  if (cb) {
    if (state.finished) process.nextTick(cb);else stream.once('finish', cb);
  }

  state.ended = true;
  stream.writable = false;
}

function onCorkedFinish(corkReq, state, err) {
  var entry = corkReq.entry;
  corkReq.entry = null;

  while (entry) {
    var cb = entry.callback;
    state.pendingcb--;
    cb(err);
    entry = entry.next;
  } // reuse the free corkReq.


  state.corkedRequestsFree.next = corkReq;
}

Object.defineProperty(Writable.prototype, 'destroyed', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    if (this._writableState === undefined) {
      return false;
    }

    return this._writableState.destroyed;
  },
  set: function set(value) {
    // we ignore the value if the stream
    // has not been initialized yet
    if (!this._writableState) {
      return;
    } // backward compatibility, the user is explicitly
    // managing destroyed


    this._writableState.destroyed = value;
  }
});
Writable.prototype.destroy = destroyImpl.destroy;
Writable.prototype._undestroy = destroyImpl.undestroy;

Writable.prototype._destroy = function (err, cb) {
  cb(err);
};
}).call(this)}).call(this,require('_process'),typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"../errors":137,"./_stream_duplex":138,"./internal/streams/destroy":145,"./internal/streams/state":149,"./internal/streams/stream":150,"_process":135,"buffer":44,"inherits":49,"util-deprecate":154}],143:[function(require,module,exports){
(function (process){(function (){
'use strict';

var _Object$setPrototypeO;

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

var finished = require('./end-of-stream');

var kLastResolve = Symbol('lastResolve');
var kLastReject = Symbol('lastReject');
var kError = Symbol('error');
var kEnded = Symbol('ended');
var kLastPromise = Symbol('lastPromise');
var kHandlePromise = Symbol('handlePromise');
var kStream = Symbol('stream');

function createIterResult(value, done) {
  return {
    value: value,
    done: done
  };
}

function readAndResolve(iter) {
  var resolve = iter[kLastResolve];

  if (resolve !== null) {
    var data = iter[kStream].read(); // we defer if data is null
    // we can be expecting either 'end' or
    // 'error'

    if (data !== null) {
      iter[kLastPromise] = null;
      iter[kLastResolve] = null;
      iter[kLastReject] = null;
      resolve(createIterResult(data, false));
    }
  }
}

function onReadable(iter) {
  // we wait for the next tick, because it might
  // emit an error with process.nextTick
  process.nextTick(readAndResolve, iter);
}

function wrapForNext(lastPromise, iter) {
  return function (resolve, reject) {
    lastPromise.then(function () {
      if (iter[kEnded]) {
        resolve(createIterResult(undefined, true));
        return;
      }

      iter[kHandlePromise](resolve, reject);
    }, reject);
  };
}

var AsyncIteratorPrototype = Object.getPrototypeOf(function () {});
var ReadableStreamAsyncIteratorPrototype = Object.setPrototypeOf((_Object$setPrototypeO = {
  get stream() {
    return this[kStream];
  },

  next: function next() {
    var _this = this;

    // if we have detected an error in the meanwhile
    // reject straight away
    var error = this[kError];

    if (error !== null) {
      return Promise.reject(error);
    }

    if (this[kEnded]) {
      return Promise.resolve(createIterResult(undefined, true));
    }

    if (this[kStream].destroyed) {
      // We need to defer via nextTick because if .destroy(err) is
      // called, the error will be emitted via nextTick, and
      // we cannot guarantee that there is no error lingering around
      // waiting to be emitted.
      return new Promise(function (resolve, reject) {
        process.nextTick(function () {
          if (_this[kError]) {
            reject(_this[kError]);
          } else {
            resolve(createIterResult(undefined, true));
          }
        });
      });
    } // if we have multiple next() calls
    // we will wait for the previous Promise to finish
    // this logic is optimized to support for await loops,
    // where next() is only called once at a time


    var lastPromise = this[kLastPromise];
    var promise;

    if (lastPromise) {
      promise = new Promise(wrapForNext(lastPromise, this));
    } else {
      // fast path needed to support multiple this.push()
      // without triggering the next() queue
      var data = this[kStream].read();

      if (data !== null) {
        return Promise.resolve(createIterResult(data, false));
      }

      promise = new Promise(this[kHandlePromise]);
    }

    this[kLastPromise] = promise;
    return promise;
  }
}, _defineProperty(_Object$setPrototypeO, Symbol.asyncIterator, function () {
  return this;
}), _defineProperty(_Object$setPrototypeO, "return", function _return() {
  var _this2 = this;

  // destroy(err, cb) is a private API
  // we can guarantee we have that here, because we control the
  // Readable class this is attached to
  return new Promise(function (resolve, reject) {
    _this2[kStream].destroy(null, function (err) {
      if (err) {
        reject(err);
        return;
      }

      resolve(createIterResult(undefined, true));
    });
  });
}), _Object$setPrototypeO), AsyncIteratorPrototype);

var createReadableStreamAsyncIterator = function createReadableStreamAsyncIterator(stream) {
  var _Object$create;

  var iterator = Object.create(ReadableStreamAsyncIteratorPrototype, (_Object$create = {}, _defineProperty(_Object$create, kStream, {
    value: stream,
    writable: true
  }), _defineProperty(_Object$create, kLastResolve, {
    value: null,
    writable: true
  }), _defineProperty(_Object$create, kLastReject, {
    value: null,
    writable: true
  }), _defineProperty(_Object$create, kError, {
    value: null,
    writable: true
  }), _defineProperty(_Object$create, kEnded, {
    value: stream._readableState.endEmitted,
    writable: true
  }), _defineProperty(_Object$create, kHandlePromise, {
    value: function value(resolve, reject) {
      var data = iterator[kStream].read();

      if (data) {
        iterator[kLastPromise] = null;
        iterator[kLastResolve] = null;
        iterator[kLastReject] = null;
        resolve(createIterResult(data, false));
      } else {
        iterator[kLastResolve] = resolve;
        iterator[kLastReject] = reject;
      }
    },
    writable: true
  }), _Object$create));
  iterator[kLastPromise] = null;
  finished(stream, function (err) {
    if (err && err.code !== 'ERR_STREAM_PREMATURE_CLOSE') {
      var reject = iterator[kLastReject]; // reject if we are waiting for data in the Promise
      // returned by next() and store the error

      if (reject !== null) {
        iterator[kLastPromise] = null;
        iterator[kLastResolve] = null;
        iterator[kLastReject] = null;
        reject(err);
      }

      iterator[kError] = err;
      return;
    }

    var resolve = iterator[kLastResolve];

    if (resolve !== null) {
      iterator[kLastPromise] = null;
      iterator[kLastResolve] = null;
      iterator[kLastReject] = null;
      resolve(createIterResult(undefined, true));
    }

    iterator[kEnded] = true;
  });
  stream.on('readable', onReadable.bind(null, iterator));
  return iterator;
};

module.exports = createReadableStreamAsyncIterator;
}).call(this)}).call(this,require('_process'))
},{"./end-of-stream":146,"_process":135}],144:[function(require,module,exports){
'use strict';

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

var _require = require('buffer'),
    Buffer = _require.Buffer;

var _require2 = require('util'),
    inspect = _require2.inspect;

var custom = inspect && inspect.custom || 'inspect';

function copyBuffer(src, target, offset) {
  Buffer.prototype.copy.call(src, target, offset);
}

module.exports =
/*#__PURE__*/
function () {
  function BufferList() {
    _classCallCheck(this, BufferList);

    this.head = null;
    this.tail = null;
    this.length = 0;
  }

  _createClass(BufferList, [{
    key: "push",
    value: function push(v) {
      var entry = {
        data: v,
        next: null
      };
      if (this.length > 0) this.tail.next = entry;else this.head = entry;
      this.tail = entry;
      ++this.length;
    }
  }, {
    key: "unshift",
    value: function unshift(v) {
      var entry = {
        data: v,
        next: this.head
      };
      if (this.length === 0) this.tail = entry;
      this.head = entry;
      ++this.length;
    }
  }, {
    key: "shift",
    value: function shift() {
      if (this.length === 0) return;
      var ret = this.head.data;
      if (this.length === 1) this.head = this.tail = null;else this.head = this.head.next;
      --this.length;
      return ret;
    }
  }, {
    key: "clear",
    value: function clear() {
      this.head = this.tail = null;
      this.length = 0;
    }
  }, {
    key: "join",
    value: function join(s) {
      if (this.length === 0) return '';
      var p = this.head;
      var ret = '' + p.data;

      while (p = p.next) {
        ret += s + p.data;
      }

      return ret;
    }
  }, {
    key: "concat",
    value: function concat(n) {
      if (this.length === 0) return Buffer.alloc(0);
      var ret = Buffer.allocUnsafe(n >>> 0);
      var p = this.head;
      var i = 0;

      while (p) {
        copyBuffer(p.data, ret, i);
        i += p.data.length;
        p = p.next;
      }

      return ret;
    } // Consumes a specified amount of bytes or characters from the buffered data.

  }, {
    key: "consume",
    value: function consume(n, hasStrings) {
      var ret;

      if (n < this.head.data.length) {
        // `slice` is the same for buffers and strings.
        ret = this.head.data.slice(0, n);
        this.head.data = this.head.data.slice(n);
      } else if (n === this.head.data.length) {
        // First chunk is a perfect match.
        ret = this.shift();
      } else {
        // Result spans more than one buffer.
        ret = hasStrings ? this._getString(n) : this._getBuffer(n);
      }

      return ret;
    }
  }, {
    key: "first",
    value: function first() {
      return this.head.data;
    } // Consumes a specified amount of characters from the buffered data.

  }, {
    key: "_getString",
    value: function _getString(n) {
      var p = this.head;
      var c = 1;
      var ret = p.data;
      n -= ret.length;

      while (p = p.next) {
        var str = p.data;
        var nb = n > str.length ? str.length : n;
        if (nb === str.length) ret += str;else ret += str.slice(0, n);
        n -= nb;

        if (n === 0) {
          if (nb === str.length) {
            ++c;
            if (p.next) this.head = p.next;else this.head = this.tail = null;
          } else {
            this.head = p;
            p.data = str.slice(nb);
          }

          break;
        }

        ++c;
      }

      this.length -= c;
      return ret;
    } // Consumes a specified amount of bytes from the buffered data.

  }, {
    key: "_getBuffer",
    value: function _getBuffer(n) {
      var ret = Buffer.allocUnsafe(n);
      var p = this.head;
      var c = 1;
      p.data.copy(ret);
      n -= p.data.length;

      while (p = p.next) {
        var buf = p.data;
        var nb = n > buf.length ? buf.length : n;
        buf.copy(ret, ret.length - n, 0, nb);
        n -= nb;

        if (n === 0) {
          if (nb === buf.length) {
            ++c;
            if (p.next) this.head = p.next;else this.head = this.tail = null;
          } else {
            this.head = p;
            p.data = buf.slice(nb);
          }

          break;
        }

        ++c;
      }

      this.length -= c;
      return ret;
    } // Make sure the linked list only shows the minimal necessary information.

  }, {
    key: custom,
    value: function value(_, options) {
      return inspect(this, _objectSpread({}, options, {
        // Only inspect one level.
        depth: 0,
        // It should not recurse.
        customInspect: false
      }));
    }
  }]);

  return BufferList;
}();
},{"buffer":44,"util":43}],145:[function(require,module,exports){
(function (process){(function (){
'use strict'; // undocumented cb() API, needed for core, not for public API

function destroy(err, cb) {
  var _this = this;

  var readableDestroyed = this._readableState && this._readableState.destroyed;
  var writableDestroyed = this._writableState && this._writableState.destroyed;

  if (readableDestroyed || writableDestroyed) {
    if (cb) {
      cb(err);
    } else if (err) {
      if (!this._writableState) {
        process.nextTick(emitErrorNT, this, err);
      } else if (!this._writableState.errorEmitted) {
        this._writableState.errorEmitted = true;
        process.nextTick(emitErrorNT, this, err);
      }
    }

    return this;
  } // we set destroyed to true before firing error callbacks in order
  // to make it re-entrance safe in case destroy() is called within callbacks


  if (this._readableState) {
    this._readableState.destroyed = true;
  } // if this is a duplex stream mark the writable part as destroyed as well


  if (this._writableState) {
    this._writableState.destroyed = true;
  }

  this._destroy(err || null, function (err) {
    if (!cb && err) {
      if (!_this._writableState) {
        process.nextTick(emitErrorAndCloseNT, _this, err);
      } else if (!_this._writableState.errorEmitted) {
        _this._writableState.errorEmitted = true;
        process.nextTick(emitErrorAndCloseNT, _this, err);
      } else {
        process.nextTick(emitCloseNT, _this);
      }
    } else if (cb) {
      process.nextTick(emitCloseNT, _this);
      cb(err);
    } else {
      process.nextTick(emitCloseNT, _this);
    }
  });

  return this;
}

function emitErrorAndCloseNT(self, err) {
  emitErrorNT(self, err);
  emitCloseNT(self);
}

function emitCloseNT(self) {
  if (self._writableState && !self._writableState.emitClose) return;
  if (self._readableState && !self._readableState.emitClose) return;
  self.emit('close');
}

function undestroy() {
  if (this._readableState) {
    this._readableState.destroyed = false;
    this._readableState.reading = false;
    this._readableState.ended = false;
    this._readableState.endEmitted = false;
  }

  if (this._writableState) {
    this._writableState.destroyed = false;
    this._writableState.ended = false;
    this._writableState.ending = false;
    this._writableState.finalCalled = false;
    this._writableState.prefinished = false;
    this._writableState.finished = false;
    this._writableState.errorEmitted = false;
  }
}

function emitErrorNT(self, err) {
  self.emit('error', err);
}

function errorOrDestroy(stream, err) {
  // We have tests that rely on errors being emitted
  // in the same tick, so changing this is semver major.
  // For now when you opt-in to autoDestroy we allow
  // the error to be emitted nextTick. In a future
  // semver major update we should change the default to this.
  var rState = stream._readableState;
  var wState = stream._writableState;
  if (rState && rState.autoDestroy || wState && wState.autoDestroy) stream.destroy(err);else stream.emit('error', err);
}

module.exports = {
  destroy: destroy,
  undestroy: undestroy,
  errorOrDestroy: errorOrDestroy
};
}).call(this)}).call(this,require('_process'))
},{"_process":135}],146:[function(require,module,exports){
// Ported from https://github.com/mafintosh/end-of-stream with
// permission from the author, Mathias Buus (@mafintosh).
'use strict';

var ERR_STREAM_PREMATURE_CLOSE = require('../../../errors').codes.ERR_STREAM_PREMATURE_CLOSE;

function once(callback) {
  var called = false;
  return function () {
    if (called) return;
    called = true;

    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    callback.apply(this, args);
  };
}

function noop() {}

function isRequest(stream) {
  return stream.setHeader && typeof stream.abort === 'function';
}

function eos(stream, opts, callback) {
  if (typeof opts === 'function') return eos(stream, null, opts);
  if (!opts) opts = {};
  callback = once(callback || noop);
  var readable = opts.readable || opts.readable !== false && stream.readable;
  var writable = opts.writable || opts.writable !== false && stream.writable;

  var onlegacyfinish = function onlegacyfinish() {
    if (!stream.writable) onfinish();
  };

  var writableEnded = stream._writableState && stream._writableState.finished;

  var onfinish = function onfinish() {
    writable = false;
    writableEnded = true;
    if (!readable) callback.call(stream);
  };

  var readableEnded = stream._readableState && stream._readableState.endEmitted;

  var onend = function onend() {
    readable = false;
    readableEnded = true;
    if (!writable) callback.call(stream);
  };

  var onerror = function onerror(err) {
    callback.call(stream, err);
  };

  var onclose = function onclose() {
    var err;

    if (readable && !readableEnded) {
      if (!stream._readableState || !stream._readableState.ended) err = new ERR_STREAM_PREMATURE_CLOSE();
      return callback.call(stream, err);
    }

    if (writable && !writableEnded) {
      if (!stream._writableState || !stream._writableState.ended) err = new ERR_STREAM_PREMATURE_CLOSE();
      return callback.call(stream, err);
    }
  };

  var onrequest = function onrequest() {
    stream.req.on('finish', onfinish);
  };

  if (isRequest(stream)) {
    stream.on('complete', onfinish);
    stream.on('abort', onclose);
    if (stream.req) onrequest();else stream.on('request', onrequest);
  } else if (writable && !stream._writableState) {
    // legacy streams
    stream.on('end', onlegacyfinish);
    stream.on('close', onlegacyfinish);
  }

  stream.on('end', onend);
  stream.on('finish', onfinish);
  if (opts.error !== false) stream.on('error', onerror);
  stream.on('close', onclose);
  return function () {
    stream.removeListener('complete', onfinish);
    stream.removeListener('abort', onclose);
    stream.removeListener('request', onrequest);
    if (stream.req) stream.req.removeListener('finish', onfinish);
    stream.removeListener('end', onlegacyfinish);
    stream.removeListener('close', onlegacyfinish);
    stream.removeListener('finish', onfinish);
    stream.removeListener('end', onend);
    stream.removeListener('error', onerror);
    stream.removeListener('close', onclose);
  };
}

module.exports = eos;
},{"../../../errors":137}],147:[function(require,module,exports){
module.exports = function () {
  throw new Error('Readable.from is not available in the browser')
};

},{}],148:[function(require,module,exports){
// Ported from https://github.com/mafintosh/pump with
// permission from the author, Mathias Buus (@mafintosh).
'use strict';

var eos;

function once(callback) {
  var called = false;
  return function () {
    if (called) return;
    called = true;
    callback.apply(void 0, arguments);
  };
}

var _require$codes = require('../../../errors').codes,
    ERR_MISSING_ARGS = _require$codes.ERR_MISSING_ARGS,
    ERR_STREAM_DESTROYED = _require$codes.ERR_STREAM_DESTROYED;

function noop(err) {
  // Rethrow the error if it exists to avoid swallowing it
  if (err) throw err;
}

function isRequest(stream) {
  return stream.setHeader && typeof stream.abort === 'function';
}

function destroyer(stream, reading, writing, callback) {
  callback = once(callback);
  var closed = false;
  stream.on('close', function () {
    closed = true;
  });
  if (eos === undefined) eos = require('./end-of-stream');
  eos(stream, {
    readable: reading,
    writable: writing
  }, function (err) {
    if (err) return callback(err);
    closed = true;
    callback();
  });
  var destroyed = false;
  return function (err) {
    if (closed) return;
    if (destroyed) return;
    destroyed = true; // request.destroy just do .end - .abort is what we want

    if (isRequest(stream)) return stream.abort();
    if (typeof stream.destroy === 'function') return stream.destroy();
    callback(err || new ERR_STREAM_DESTROYED('pipe'));
  };
}

function call(fn) {
  fn();
}

function pipe(from, to) {
  return from.pipe(to);
}

function popCallback(streams) {
  if (!streams.length) return noop;
  if (typeof streams[streams.length - 1] !== 'function') return noop;
  return streams.pop();
}

function pipeline() {
  for (var _len = arguments.length, streams = new Array(_len), _key = 0; _key < _len; _key++) {
    streams[_key] = arguments[_key];
  }

  var callback = popCallback(streams);
  if (Array.isArray(streams[0])) streams = streams[0];

  if (streams.length < 2) {
    throw new ERR_MISSING_ARGS('streams');
  }

  var error;
  var destroys = streams.map(function (stream, i) {
    var reading = i < streams.length - 1;
    var writing = i > 0;
    return destroyer(stream, reading, writing, function (err) {
      if (!error) error = err;
      if (err) destroys.forEach(call);
      if (reading) return;
      destroys.forEach(call);
      callback(error);
    });
  });
  return streams.reduce(pipe);
}

module.exports = pipeline;
},{"../../../errors":137,"./end-of-stream":146}],149:[function(require,module,exports){
'use strict';

var ERR_INVALID_OPT_VALUE = require('../../../errors').codes.ERR_INVALID_OPT_VALUE;

function highWaterMarkFrom(options, isDuplex, duplexKey) {
  return options.highWaterMark != null ? options.highWaterMark : isDuplex ? options[duplexKey] : null;
}

function getHighWaterMark(state, options, duplexKey, isDuplex) {
  var hwm = highWaterMarkFrom(options, isDuplex, duplexKey);

  if (hwm != null) {
    if (!(isFinite(hwm) && Math.floor(hwm) === hwm) || hwm < 0) {
      var name = isDuplex ? duplexKey : 'highWaterMark';
      throw new ERR_INVALID_OPT_VALUE(name, hwm);
    }

    return Math.floor(hwm);
  } // Default value


  return state.objectMode ? 16 : 16 * 1024;
}

module.exports = {
  getHighWaterMark: getHighWaterMark
};
},{"../../../errors":137}],150:[function(require,module,exports){
module.exports = require('events').EventEmitter;

},{"events":46}],151:[function(require,module,exports){
exports = module.exports = require('./lib/_stream_readable.js');
exports.Stream = exports;
exports.Readable = exports;
exports.Writable = require('./lib/_stream_writable.js');
exports.Duplex = require('./lib/_stream_duplex.js');
exports.Transform = require('./lib/_stream_transform.js');
exports.PassThrough = require('./lib/_stream_passthrough.js');
exports.finished = require('./lib/internal/streams/end-of-stream.js');
exports.pipeline = require('./lib/internal/streams/pipeline.js');

},{"./lib/_stream_duplex.js":138,"./lib/_stream_passthrough.js":139,"./lib/_stream_readable.js":140,"./lib/_stream_transform.js":141,"./lib/_stream_writable.js":142,"./lib/internal/streams/end-of-stream.js":146,"./lib/internal/streams/pipeline.js":148}],152:[function(require,module,exports){
/*! safe-buffer. MIT License. Feross Aboukhadijeh <https://feross.org/opensource> */
/* eslint-disable node/no-deprecated-api */
var buffer = require('buffer')
var Buffer = buffer.Buffer

// alternative to using Object.keys for old browsers
function copyProps (src, dst) {
  for (var key in src) {
    dst[key] = src[key]
  }
}
if (Buffer.from && Buffer.alloc && Buffer.allocUnsafe && Buffer.allocUnsafeSlow) {
  module.exports = buffer
} else {
  // Copy properties from require('buffer')
  copyProps(buffer, exports)
  exports.Buffer = SafeBuffer
}

function SafeBuffer (arg, encodingOrOffset, length) {
  return Buffer(arg, encodingOrOffset, length)
}

SafeBuffer.prototype = Object.create(Buffer.prototype)

// Copy static methods from Buffer
copyProps(Buffer, SafeBuffer)

SafeBuffer.from = function (arg, encodingOrOffset, length) {
  if (typeof arg === 'number') {
    throw new TypeError('Argument must not be a number')
  }
  return Buffer(arg, encodingOrOffset, length)
}

SafeBuffer.alloc = function (size, fill, encoding) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  var buf = Buffer(size)
  if (fill !== undefined) {
    if (typeof encoding === 'string') {
      buf.fill(fill, encoding)
    } else {
      buf.fill(fill)
    }
  } else {
    buf.fill(0)
  }
  return buf
}

SafeBuffer.allocUnsafe = function (size) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  return Buffer(size)
}

SafeBuffer.allocUnsafeSlow = function (size) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  return buffer.SlowBuffer(size)
}

},{"buffer":44}],153:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

/*<replacement>*/

var Buffer = require('safe-buffer').Buffer;
/*</replacement>*/

var isEncoding = Buffer.isEncoding || function (encoding) {
  encoding = '' + encoding;
  switch (encoding && encoding.toLowerCase()) {
    case 'hex':case 'utf8':case 'utf-8':case 'ascii':case 'binary':case 'base64':case 'ucs2':case 'ucs-2':case 'utf16le':case 'utf-16le':case 'raw':
      return true;
    default:
      return false;
  }
};

function _normalizeEncoding(enc) {
  if (!enc) return 'utf8';
  var retried;
  while (true) {
    switch (enc) {
      case 'utf8':
      case 'utf-8':
        return 'utf8';
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return 'utf16le';
      case 'latin1':
      case 'binary':
        return 'latin1';
      case 'base64':
      case 'ascii':
      case 'hex':
        return enc;
      default:
        if (retried) return; // undefined
        enc = ('' + enc).toLowerCase();
        retried = true;
    }
  }
};

// Do not cache `Buffer.isEncoding` when checking encoding names as some
// modules monkey-patch it to support additional encodings
function normalizeEncoding(enc) {
  var nenc = _normalizeEncoding(enc);
  if (typeof nenc !== 'string' && (Buffer.isEncoding === isEncoding || !isEncoding(enc))) throw new Error('Unknown encoding: ' + enc);
  return nenc || enc;
}

// StringDecoder provides an interface for efficiently splitting a series of
// buffers into a series of JS strings without breaking apart multi-byte
// characters.
exports.StringDecoder = StringDecoder;
function StringDecoder(encoding) {
  this.encoding = normalizeEncoding(encoding);
  var nb;
  switch (this.encoding) {
    case 'utf16le':
      this.text = utf16Text;
      this.end = utf16End;
      nb = 4;
      break;
    case 'utf8':
      this.fillLast = utf8FillLast;
      nb = 4;
      break;
    case 'base64':
      this.text = base64Text;
      this.end = base64End;
      nb = 3;
      break;
    default:
      this.write = simpleWrite;
      this.end = simpleEnd;
      return;
  }
  this.lastNeed = 0;
  this.lastTotal = 0;
  this.lastChar = Buffer.allocUnsafe(nb);
}

StringDecoder.prototype.write = function (buf) {
  if (buf.length === 0) return '';
  var r;
  var i;
  if (this.lastNeed) {
    r = this.fillLast(buf);
    if (r === undefined) return '';
    i = this.lastNeed;
    this.lastNeed = 0;
  } else {
    i = 0;
  }
  if (i < buf.length) return r ? r + this.text(buf, i) : this.text(buf, i);
  return r || '';
};

StringDecoder.prototype.end = utf8End;

// Returns only complete characters in a Buffer
StringDecoder.prototype.text = utf8Text;

// Attempts to complete a partial non-UTF-8 character using bytes from a Buffer
StringDecoder.prototype.fillLast = function (buf) {
  if (this.lastNeed <= buf.length) {
    buf.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, this.lastNeed);
    return this.lastChar.toString(this.encoding, 0, this.lastTotal);
  }
  buf.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, buf.length);
  this.lastNeed -= buf.length;
};

// Checks the type of a UTF-8 byte, whether it's ASCII, a leading byte, or a
// continuation byte. If an invalid byte is detected, -2 is returned.
function utf8CheckByte(byte) {
  if (byte <= 0x7F) return 0;else if (byte >> 5 === 0x06) return 2;else if (byte >> 4 === 0x0E) return 3;else if (byte >> 3 === 0x1E) return 4;
  return byte >> 6 === 0x02 ? -1 : -2;
}

// Checks at most 3 bytes at the end of a Buffer in order to detect an
// incomplete multi-byte UTF-8 character. The total number of bytes (2, 3, or 4)
// needed to complete the UTF-8 character (if applicable) are returned.
function utf8CheckIncomplete(self, buf, i) {
  var j = buf.length - 1;
  if (j < i) return 0;
  var nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) self.lastNeed = nb - 1;
    return nb;
  }
  if (--j < i || nb === -2) return 0;
  nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) self.lastNeed = nb - 2;
    return nb;
  }
  if (--j < i || nb === -2) return 0;
  nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) {
      if (nb === 2) nb = 0;else self.lastNeed = nb - 3;
    }
    return nb;
  }
  return 0;
}

// Validates as many continuation bytes for a multi-byte UTF-8 character as
// needed or are available. If we see a non-continuation byte where we expect
// one, we "replace" the validated continuation bytes we've seen so far with
// a single UTF-8 replacement character ('\ufffd'), to match v8's UTF-8 decoding
// behavior. The continuation byte check is included three times in the case
// where all of the continuation bytes for a character exist in the same buffer.
// It is also done this way as a slight performance increase instead of using a
// loop.
function utf8CheckExtraBytes(self, buf, p) {
  if ((buf[0] & 0xC0) !== 0x80) {
    self.lastNeed = 0;
    return '\ufffd';
  }
  if (self.lastNeed > 1 && buf.length > 1) {
    if ((buf[1] & 0xC0) !== 0x80) {
      self.lastNeed = 1;
      return '\ufffd';
    }
    if (self.lastNeed > 2 && buf.length > 2) {
      if ((buf[2] & 0xC0) !== 0x80) {
        self.lastNeed = 2;
        return '\ufffd';
      }
    }
  }
}

// Attempts to complete a multi-byte UTF-8 character using bytes from a Buffer.
function utf8FillLast(buf) {
  var p = this.lastTotal - this.lastNeed;
  var r = utf8CheckExtraBytes(this, buf, p);
  if (r !== undefined) return r;
  if (this.lastNeed <= buf.length) {
    buf.copy(this.lastChar, p, 0, this.lastNeed);
    return this.lastChar.toString(this.encoding, 0, this.lastTotal);
  }
  buf.copy(this.lastChar, p, 0, buf.length);
  this.lastNeed -= buf.length;
}

// Returns all complete UTF-8 characters in a Buffer. If the Buffer ended on a
// partial character, the character's bytes are buffered until the required
// number of bytes are available.
function utf8Text(buf, i) {
  var total = utf8CheckIncomplete(this, buf, i);
  if (!this.lastNeed) return buf.toString('utf8', i);
  this.lastTotal = total;
  var end = buf.length - (total - this.lastNeed);
  buf.copy(this.lastChar, 0, end);
  return buf.toString('utf8', i, end);
}

// For UTF-8, a replacement character is added when ending on a partial
// character.
function utf8End(buf) {
  var r = buf && buf.length ? this.write(buf) : '';
  if (this.lastNeed) return r + '\ufffd';
  return r;
}

// UTF-16LE typically needs two bytes per character, but even if we have an even
// number of bytes available, we need to check if we end on a leading/high
// surrogate. In that case, we need to wait for the next two bytes in order to
// decode the last character properly.
function utf16Text(buf, i) {
  if ((buf.length - i) % 2 === 0) {
    var r = buf.toString('utf16le', i);
    if (r) {
      var c = r.charCodeAt(r.length - 1);
      if (c >= 0xD800 && c <= 0xDBFF) {
        this.lastNeed = 2;
        this.lastTotal = 4;
        this.lastChar[0] = buf[buf.length - 2];
        this.lastChar[1] = buf[buf.length - 1];
        return r.slice(0, -1);
      }
    }
    return r;
  }
  this.lastNeed = 1;
  this.lastTotal = 2;
  this.lastChar[0] = buf[buf.length - 1];
  return buf.toString('utf16le', i, buf.length - 1);
}

// For UTF-16LE we do not explicitly append special replacement characters if we
// end on a partial character, we simply let v8 handle that.
function utf16End(buf) {
  var r = buf && buf.length ? this.write(buf) : '';
  if (this.lastNeed) {
    var end = this.lastTotal - this.lastNeed;
    return r + this.lastChar.toString('utf16le', 0, end);
  }
  return r;
}

function base64Text(buf, i) {
  var n = (buf.length - i) % 3;
  if (n === 0) return buf.toString('base64', i);
  this.lastNeed = 3 - n;
  this.lastTotal = 3;
  if (n === 1) {
    this.lastChar[0] = buf[buf.length - 1];
  } else {
    this.lastChar[0] = buf[buf.length - 2];
    this.lastChar[1] = buf[buf.length - 1];
  }
  return buf.toString('base64', i, buf.length - n);
}

function base64End(buf) {
  var r = buf && buf.length ? this.write(buf) : '';
  if (this.lastNeed) return r + this.lastChar.toString('base64', 0, 3 - this.lastNeed);
  return r;
}

// Pass bytes on through for single-byte encodings (e.g. ascii, latin1, hex)
function simpleWrite(buf) {
  return buf.toString(this.encoding);
}

function simpleEnd(buf) {
  return buf && buf.length ? this.write(buf) : '';
}
},{"safe-buffer":152}],154:[function(require,module,exports){
(function (global){(function (){

/**
 * Module exports.
 */

module.exports = deprecate;

/**
 * Mark that a method should not be used.
 * Returns a modified function which warns once by default.
 *
 * If `localStorage.noDeprecation = true` is set, then it is a no-op.
 *
 * If `localStorage.throwDeprecation = true` is set, then deprecated functions
 * will throw an Error when invoked.
 *
 * If `localStorage.traceDeprecation = true` is set, then deprecated functions
 * will invoke `console.trace()` instead of `console.error()`.
 *
 * @param {Function} fn - the function to deprecate
 * @param {String} msg - the string to print to the console when `fn` is invoked
 * @returns {Function} a new "deprecated" version of `fn`
 * @api public
 */

function deprecate (fn, msg) {
  if (config('noDeprecation')) {
    return fn;
  }

  var warned = false;
  function deprecated() {
    if (!warned) {
      if (config('throwDeprecation')) {
        throw new Error(msg);
      } else if (config('traceDeprecation')) {
        console.trace(msg);
      } else {
        console.warn(msg);
      }
      warned = true;
    }
    return fn.apply(this, arguments);
  }

  return deprecated;
}

/**
 * Checks `localStorage` for boolean values for the given `name`.
 *
 * @param {String} name
 * @returns {Boolean}
 * @api private
 */

function config (name) {
  // accessing global.localStorage can trigger a DOMException in sandboxed iframes
  try {
    if (!global.localStorage) return false;
  } catch (_) {
    return false;
  }
  var val = global.localStorage[name];
  if (null == val) return false;
  return String(val).toLowerCase() === 'true';
}

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],155:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
Object.defineProperty(exports, "v1", {
  enumerable: true,
  get: function () {
    return _v.default;
  }
});
Object.defineProperty(exports, "v3", {
  enumerable: true,
  get: function () {
    return _v2.default;
  }
});
Object.defineProperty(exports, "v4", {
  enumerable: true,
  get: function () {
    return _v3.default;
  }
});
Object.defineProperty(exports, "v5", {
  enumerable: true,
  get: function () {
    return _v4.default;
  }
});
Object.defineProperty(exports, "NIL", {
  enumerable: true,
  get: function () {
    return _nil.default;
  }
});
Object.defineProperty(exports, "version", {
  enumerable: true,
  get: function () {
    return _version.default;
  }
});
Object.defineProperty(exports, "validate", {
  enumerable: true,
  get: function () {
    return _validate.default;
  }
});
Object.defineProperty(exports, "stringify", {
  enumerable: true,
  get: function () {
    return _stringify.default;
  }
});
Object.defineProperty(exports, "parse", {
  enumerable: true,
  get: function () {
    return _parse.default;
  }
});

var _v = _interopRequireDefault(require("./v1.js"));

var _v2 = _interopRequireDefault(require("./v3.js"));

var _v3 = _interopRequireDefault(require("./v4.js"));

var _v4 = _interopRequireDefault(require("./v5.js"));

var _nil = _interopRequireDefault(require("./nil.js"));

var _version = _interopRequireDefault(require("./version.js"));

var _validate = _interopRequireDefault(require("./validate.js"));

var _stringify = _interopRequireDefault(require("./stringify.js"));

var _parse = _interopRequireDefault(require("./parse.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }
},{"./nil.js":157,"./parse.js":158,"./stringify.js":162,"./v1.js":163,"./v3.js":164,"./v4.js":166,"./v5.js":167,"./validate.js":168,"./version.js":169}],156:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Browser-compatible JavaScript MD5
 *
 * Modification of JavaScript MD5
 * https://github.com/blueimp/JavaScript-MD5
 *
 * Copyright 2011, Sebastian Tschan
 * https://blueimp.net
 *
 * Licensed under the MIT license:
 * https://opensource.org/licenses/MIT
 *
 * Based on
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.2 Copyright (C) Paul Johnston 1999 - 2009
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 */
function md5(bytes) {
  if (typeof bytes === 'string') {
    const msg = unescape(encodeURIComponent(bytes)); // UTF8 escape

    bytes = new Uint8Array(msg.length);

    for (let i = 0; i < msg.length; ++i) {
      bytes[i] = msg.charCodeAt(i);
    }
  }

  return md5ToHexEncodedArray(wordsToMd5(bytesToWords(bytes), bytes.length * 8));
}
/*
 * Convert an array of little-endian words to an array of bytes
 */


function md5ToHexEncodedArray(input) {
  const output = [];
  const length32 = input.length * 32;
  const hexTab = '0123456789abcdef';

  for (let i = 0; i < length32; i += 8) {
    const x = input[i >> 5] >>> i % 32 & 0xff;
    const hex = parseInt(hexTab.charAt(x >>> 4 & 0x0f) + hexTab.charAt(x & 0x0f), 16);
    output.push(hex);
  }

  return output;
}
/**
 * Calculate output length with padding and bit length
 */


function getOutputLength(inputLength8) {
  return (inputLength8 + 64 >>> 9 << 4) + 14 + 1;
}
/*
 * Calculate the MD5 of an array of little-endian words, and a bit length.
 */


function wordsToMd5(x, len) {
  /* append padding */
  x[len >> 5] |= 0x80 << len % 32;
  x[getOutputLength(len) - 1] = len;
  let a = 1732584193;
  let b = -271733879;
  let c = -1732584194;
  let d = 271733878;

  for (let i = 0; i < x.length; i += 16) {
    const olda = a;
    const oldb = b;
    const oldc = c;
    const oldd = d;
    a = md5ff(a, b, c, d, x[i], 7, -680876936);
    d = md5ff(d, a, b, c, x[i + 1], 12, -389564586);
    c = md5ff(c, d, a, b, x[i + 2], 17, 606105819);
    b = md5ff(b, c, d, a, x[i + 3], 22, -1044525330);
    a = md5ff(a, b, c, d, x[i + 4], 7, -176418897);
    d = md5ff(d, a, b, c, x[i + 5], 12, 1200080426);
    c = md5ff(c, d, a, b, x[i + 6], 17, -1473231341);
    b = md5ff(b, c, d, a, x[i + 7], 22, -45705983);
    a = md5ff(a, b, c, d, x[i + 8], 7, 1770035416);
    d = md5ff(d, a, b, c, x[i + 9], 12, -1958414417);
    c = md5ff(c, d, a, b, x[i + 10], 17, -42063);
    b = md5ff(b, c, d, a, x[i + 11], 22, -1990404162);
    a = md5ff(a, b, c, d, x[i + 12], 7, 1804603682);
    d = md5ff(d, a, b, c, x[i + 13], 12, -40341101);
    c = md5ff(c, d, a, b, x[i + 14], 17, -1502002290);
    b = md5ff(b, c, d, a, x[i + 15], 22, 1236535329);
    a = md5gg(a, b, c, d, x[i + 1], 5, -165796510);
    d = md5gg(d, a, b, c, x[i + 6], 9, -1069501632);
    c = md5gg(c, d, a, b, x[i + 11], 14, 643717713);
    b = md5gg(b, c, d, a, x[i], 20, -373897302);
    a = md5gg(a, b, c, d, x[i + 5], 5, -701558691);
    d = md5gg(d, a, b, c, x[i + 10], 9, 38016083);
    c = md5gg(c, d, a, b, x[i + 15], 14, -660478335);
    b = md5gg(b, c, d, a, x[i + 4], 20, -405537848);
    a = md5gg(a, b, c, d, x[i + 9], 5, 568446438);
    d = md5gg(d, a, b, c, x[i + 14], 9, -1019803690);
    c = md5gg(c, d, a, b, x[i + 3], 14, -187363961);
    b = md5gg(b, c, d, a, x[i + 8], 20, 1163531501);
    a = md5gg(a, b, c, d, x[i + 13], 5, -1444681467);
    d = md5gg(d, a, b, c, x[i + 2], 9, -51403784);
    c = md5gg(c, d, a, b, x[i + 7], 14, 1735328473);
    b = md5gg(b, c, d, a, x[i + 12], 20, -1926607734);
    a = md5hh(a, b, c, d, x[i + 5], 4, -378558);
    d = md5hh(d, a, b, c, x[i + 8], 11, -2022574463);
    c = md5hh(c, d, a, b, x[i + 11], 16, 1839030562);
    b = md5hh(b, c, d, a, x[i + 14], 23, -35309556);
    a = md5hh(a, b, c, d, x[i + 1], 4, -1530992060);
    d = md5hh(d, a, b, c, x[i + 4], 11, 1272893353);
    c = md5hh(c, d, a, b, x[i + 7], 16, -155497632);
    b = md5hh(b, c, d, a, x[i + 10], 23, -1094730640);
    a = md5hh(a, b, c, d, x[i + 13], 4, 681279174);
    d = md5hh(d, a, b, c, x[i], 11, -358537222);
    c = md5hh(c, d, a, b, x[i + 3], 16, -722521979);
    b = md5hh(b, c, d, a, x[i + 6], 23, 76029189);
    a = md5hh(a, b, c, d, x[i + 9], 4, -640364487);
    d = md5hh(d, a, b, c, x[i + 12], 11, -421815835);
    c = md5hh(c, d, a, b, x[i + 15], 16, 530742520);
    b = md5hh(b, c, d, a, x[i + 2], 23, -995338651);
    a = md5ii(a, b, c, d, x[i], 6, -198630844);
    d = md5ii(d, a, b, c, x[i + 7], 10, 1126891415);
    c = md5ii(c, d, a, b, x[i + 14], 15, -1416354905);
    b = md5ii(b, c, d, a, x[i + 5], 21, -57434055);
    a = md5ii(a, b, c, d, x[i + 12], 6, 1700485571);
    d = md5ii(d, a, b, c, x[i + 3], 10, -1894986606);
    c = md5ii(c, d, a, b, x[i + 10], 15, -1051523);
    b = md5ii(b, c, d, a, x[i + 1], 21, -2054922799);
    a = md5ii(a, b, c, d, x[i + 8], 6, 1873313359);
    d = md5ii(d, a, b, c, x[i + 15], 10, -30611744);
    c = md5ii(c, d, a, b, x[i + 6], 15, -1560198380);
    b = md5ii(b, c, d, a, x[i + 13], 21, 1309151649);
    a = md5ii(a, b, c, d, x[i + 4], 6, -145523070);
    d = md5ii(d, a, b, c, x[i + 11], 10, -1120210379);
    c = md5ii(c, d, a, b, x[i + 2], 15, 718787259);
    b = md5ii(b, c, d, a, x[i + 9], 21, -343485551);
    a = safeAdd(a, olda);
    b = safeAdd(b, oldb);
    c = safeAdd(c, oldc);
    d = safeAdd(d, oldd);
  }

  return [a, b, c, d];
}
/*
 * Convert an array bytes to an array of little-endian words
 * Characters >255 have their high-byte silently ignored.
 */


function bytesToWords(input) {
  if (input.length === 0) {
    return [];
  }

  const length8 = input.length * 8;
  const output = new Uint32Array(getOutputLength(length8));

  for (let i = 0; i < length8; i += 8) {
    output[i >> 5] |= (input[i / 8] & 0xff) << i % 32;
  }

  return output;
}
/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */


function safeAdd(x, y) {
  const lsw = (x & 0xffff) + (y & 0xffff);
  const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return msw << 16 | lsw & 0xffff;
}
/*
 * Bitwise rotate a 32-bit number to the left.
 */


function bitRotateLeft(num, cnt) {
  return num << cnt | num >>> 32 - cnt;
}
/*
 * These functions implement the four basic operations the algorithm uses.
 */


function md5cmn(q, a, b, x, s, t) {
  return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
}

function md5ff(a, b, c, d, x, s, t) {
  return md5cmn(b & c | ~b & d, a, b, x, s, t);
}

function md5gg(a, b, c, d, x, s, t) {
  return md5cmn(b & d | c & ~d, a, b, x, s, t);
}

function md5hh(a, b, c, d, x, s, t) {
  return md5cmn(b ^ c ^ d, a, b, x, s, t);
}

function md5ii(a, b, c, d, x, s, t) {
  return md5cmn(c ^ (b | ~d), a, b, x, s, t);
}

var _default = md5;
exports.default = _default;
},{}],157:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _default = '00000000-0000-0000-0000-000000000000';
exports.default = _default;
},{}],158:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _validate = _interopRequireDefault(require("./validate.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function parse(uuid) {
  if (!(0, _validate.default)(uuid)) {
    throw TypeError('Invalid UUID');
  }

  let v;
  const arr = new Uint8Array(16); // Parse ########-....-....-....-............

  arr[0] = (v = parseInt(uuid.slice(0, 8), 16)) >>> 24;
  arr[1] = v >>> 16 & 0xff;
  arr[2] = v >>> 8 & 0xff;
  arr[3] = v & 0xff; // Parse ........-####-....-....-............

  arr[4] = (v = parseInt(uuid.slice(9, 13), 16)) >>> 8;
  arr[5] = v & 0xff; // Parse ........-....-####-....-............

  arr[6] = (v = parseInt(uuid.slice(14, 18), 16)) >>> 8;
  arr[7] = v & 0xff; // Parse ........-....-....-####-............

  arr[8] = (v = parseInt(uuid.slice(19, 23), 16)) >>> 8;
  arr[9] = v & 0xff; // Parse ........-....-....-....-############
  // (Use "/" to avoid 32-bit truncation when bit-shifting high-order bytes)

  arr[10] = (v = parseInt(uuid.slice(24, 36), 16)) / 0x10000000000 & 0xff;
  arr[11] = v / 0x100000000 & 0xff;
  arr[12] = v >>> 24 & 0xff;
  arr[13] = v >>> 16 & 0xff;
  arr[14] = v >>> 8 & 0xff;
  arr[15] = v & 0xff;
  return arr;
}

var _default = parse;
exports.default = _default;
},{"./validate.js":168}],159:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _default = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;
exports.default = _default;
},{}],160:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = rng;
// Unique ID creation requires a high quality random # generator. In the browser we therefore
// require the crypto API and do not support built-in fallback to lower quality random number
// generators (like Math.random()).
let getRandomValues;
const rnds8 = new Uint8Array(16);

function rng() {
  // lazy load so that environments that need to polyfill have a chance to do so
  if (!getRandomValues) {
    // getRandomValues needs to be invoked in a context where "this" is a Crypto implementation. Also,
    // find the complete implementation of crypto (msCrypto) on IE11.
    getRandomValues = typeof crypto !== 'undefined' && crypto.getRandomValues && crypto.getRandomValues.bind(crypto) || typeof msCrypto !== 'undefined' && typeof msCrypto.getRandomValues === 'function' && msCrypto.getRandomValues.bind(msCrypto);

    if (!getRandomValues) {
      throw new Error('crypto.getRandomValues() not supported. See https://github.com/uuidjs/uuid#getrandomvalues-not-supported');
    }
  }

  return getRandomValues(rnds8);
}
},{}],161:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

// Adapted from Chris Veness' SHA1 code at
// http://www.movable-type.co.uk/scripts/sha1.html
function f(s, x, y, z) {
  switch (s) {
    case 0:
      return x & y ^ ~x & z;

    case 1:
      return x ^ y ^ z;

    case 2:
      return x & y ^ x & z ^ y & z;

    case 3:
      return x ^ y ^ z;
  }
}

function ROTL(x, n) {
  return x << n | x >>> 32 - n;
}

function sha1(bytes) {
  const K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];
  const H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

  if (typeof bytes === 'string') {
    const msg = unescape(encodeURIComponent(bytes)); // UTF8 escape

    bytes = [];

    for (let i = 0; i < msg.length; ++i) {
      bytes.push(msg.charCodeAt(i));
    }
  } else if (!Array.isArray(bytes)) {
    // Convert Array-like to Array
    bytes = Array.prototype.slice.call(bytes);
  }

  bytes.push(0x80);
  const l = bytes.length / 4 + 2;
  const N = Math.ceil(l / 16);
  const M = new Array(N);

  for (let i = 0; i < N; ++i) {
    const arr = new Uint32Array(16);

    for (let j = 0; j < 16; ++j) {
      arr[j] = bytes[i * 64 + j * 4] << 24 | bytes[i * 64 + j * 4 + 1] << 16 | bytes[i * 64 + j * 4 + 2] << 8 | bytes[i * 64 + j * 4 + 3];
    }

    M[i] = arr;
  }

  M[N - 1][14] = (bytes.length - 1) * 8 / Math.pow(2, 32);
  M[N - 1][14] = Math.floor(M[N - 1][14]);
  M[N - 1][15] = (bytes.length - 1) * 8 & 0xffffffff;

  for (let i = 0; i < N; ++i) {
    const W = new Uint32Array(80);

    for (let t = 0; t < 16; ++t) {
      W[t] = M[i][t];
    }

    for (let t = 16; t < 80; ++t) {
      W[t] = ROTL(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }

    let a = H[0];
    let b = H[1];
    let c = H[2];
    let d = H[3];
    let e = H[4];

    for (let t = 0; t < 80; ++t) {
      const s = Math.floor(t / 20);
      const T = ROTL(a, 5) + f(s, b, c, d) + e + K[s] + W[t] >>> 0;
      e = d;
      d = c;
      c = ROTL(b, 30) >>> 0;
      b = a;
      a = T;
    }

    H[0] = H[0] + a >>> 0;
    H[1] = H[1] + b >>> 0;
    H[2] = H[2] + c >>> 0;
    H[3] = H[3] + d >>> 0;
    H[4] = H[4] + e >>> 0;
  }

  return [H[0] >> 24 & 0xff, H[0] >> 16 & 0xff, H[0] >> 8 & 0xff, H[0] & 0xff, H[1] >> 24 & 0xff, H[1] >> 16 & 0xff, H[1] >> 8 & 0xff, H[1] & 0xff, H[2] >> 24 & 0xff, H[2] >> 16 & 0xff, H[2] >> 8 & 0xff, H[2] & 0xff, H[3] >> 24 & 0xff, H[3] >> 16 & 0xff, H[3] >> 8 & 0xff, H[3] & 0xff, H[4] >> 24 & 0xff, H[4] >> 16 & 0xff, H[4] >> 8 & 0xff, H[4] & 0xff];
}

var _default = sha1;
exports.default = _default;
},{}],162:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _validate = _interopRequireDefault(require("./validate.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * Convert array of 16 byte values to UUID string format of the form:
 * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 */
const byteToHex = [];

for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 0x100).toString(16).substr(1));
}

function stringify(arr, offset = 0) {
  // Note: Be careful editing this code!  It's been tuned for performance
  // and works in ways you may not expect. See https://github.com/uuidjs/uuid/pull/434
  const uuid = (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase(); // Consistency check for valid UUID.  If this throws, it's likely due to one
  // of the following:
  // - One or more input array values don't map to a hex octet (leading to
  // "undefined" in the uuid)
  // - Invalid input values for the RFC `version` or `variant` fields

  if (!(0, _validate.default)(uuid)) {
    throw TypeError('Stringified UUID is invalid');
  }

  return uuid;
}

var _default = stringify;
exports.default = _default;
},{"./validate.js":168}],163:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _rng = _interopRequireDefault(require("./rng.js"));

var _stringify = _interopRequireDefault(require("./stringify.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// **`v1()` - Generate time-based UUID**
//
// Inspired by https://github.com/LiosK/UUID.js
// and http://docs.python.org/library/uuid.html
let _nodeId;

let _clockseq; // Previous uuid creation time


let _lastMSecs = 0;
let _lastNSecs = 0; // See https://github.com/uuidjs/uuid for API details

function v1(options, buf, offset) {
  let i = buf && offset || 0;
  const b = buf || new Array(16);
  options = options || {};
  let node = options.node || _nodeId;
  let clockseq = options.clockseq !== undefined ? options.clockseq : _clockseq; // node and clockseq need to be initialized to random values if they're not
  // specified.  We do this lazily to minimize issues related to insufficient
  // system entropy.  See #189

  if (node == null || clockseq == null) {
    const seedBytes = options.random || (options.rng || _rng.default)();

    if (node == null) {
      // Per 4.5, create and 48-bit node id, (47 random bits + multicast bit = 1)
      node = _nodeId = [seedBytes[0] | 0x01, seedBytes[1], seedBytes[2], seedBytes[3], seedBytes[4], seedBytes[5]];
    }

    if (clockseq == null) {
      // Per 4.2.2, randomize (14 bit) clockseq
      clockseq = _clockseq = (seedBytes[6] << 8 | seedBytes[7]) & 0x3fff;
    }
  } // UUID timestamps are 100 nano-second units since the Gregorian epoch,
  // (1582-10-15 00:00).  JSNumbers aren't precise enough for this, so
  // time is handled internally as 'msecs' (integer milliseconds) and 'nsecs'
  // (100-nanoseconds offset from msecs) since unix epoch, 1970-01-01 00:00.


  let msecs = options.msecs !== undefined ? options.msecs : Date.now(); // Per 4.2.1.2, use count of uuid's generated during the current clock
  // cycle to simulate higher resolution clock

  let nsecs = options.nsecs !== undefined ? options.nsecs : _lastNSecs + 1; // Time since last uuid creation (in msecs)

  const dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 10000; // Per 4.2.1.2, Bump clockseq on clock regression

  if (dt < 0 && options.clockseq === undefined) {
    clockseq = clockseq + 1 & 0x3fff;
  } // Reset nsecs if clock regresses (new clockseq) or we've moved onto a new
  // time interval


  if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === undefined) {
    nsecs = 0;
  } // Per 4.2.1.2 Throw error if too many uuids are requested


  if (nsecs >= 10000) {
    throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
  }

  _lastMSecs = msecs;
  _lastNSecs = nsecs;
  _clockseq = clockseq; // Per 4.1.4 - Convert from unix epoch to Gregorian epoch

  msecs += 12219292800000; // `time_low`

  const tl = ((msecs & 0xfffffff) * 10000 + nsecs) % 0x100000000;
  b[i++] = tl >>> 24 & 0xff;
  b[i++] = tl >>> 16 & 0xff;
  b[i++] = tl >>> 8 & 0xff;
  b[i++] = tl & 0xff; // `time_mid`

  const tmh = msecs / 0x100000000 * 10000 & 0xfffffff;
  b[i++] = tmh >>> 8 & 0xff;
  b[i++] = tmh & 0xff; // `time_high_and_version`

  b[i++] = tmh >>> 24 & 0xf | 0x10; // include version

  b[i++] = tmh >>> 16 & 0xff; // `clock_seq_hi_and_reserved` (Per 4.2.2 - include variant)

  b[i++] = clockseq >>> 8 | 0x80; // `clock_seq_low`

  b[i++] = clockseq & 0xff; // `node`

  for (let n = 0; n < 6; ++n) {
    b[i + n] = node[n];
  }

  return buf || (0, _stringify.default)(b);
}

var _default = v1;
exports.default = _default;
},{"./rng.js":160,"./stringify.js":162}],164:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _v = _interopRequireDefault(require("./v35.js"));

var _md = _interopRequireDefault(require("./md5.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const v3 = (0, _v.default)('v3', 0x30, _md.default);
var _default = v3;
exports.default = _default;
},{"./md5.js":156,"./v35.js":165}],165:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = _default;
exports.URL = exports.DNS = void 0;

var _stringify = _interopRequireDefault(require("./stringify.js"));

var _parse = _interopRequireDefault(require("./parse.js"));

function _interopRequireDefault(obj) {
  return obj && obj.__esModule ? obj : {
    default: obj
  };
}

function stringToBytes(str) {
  str = unescape(encodeURIComponent(str)); // UTF8 escape

  const bytes = [];

  for (let i = 0; i < str.length; ++i) {
    bytes.push(str.charCodeAt(i));
  }

  return bytes;
}

const DNS = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
exports.DNS = DNS;
const URL = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';
exports.URL = URL;

function _default(name, version, hashfunc) {
  function generateUUID(value, namespace, buf, offset) {
    if (typeof value === 'string') {
      value = stringToBytes(value);
    }

    if (typeof namespace === 'string') {
      namespace = (0, _parse.default)(namespace);
    }

    if (namespace.length !== 16) {
      throw TypeError('Namespace must be array-like (16 iterable integer values, 0-255)');
    } // Compute hash of namespace and value, Per 4.3
    // Future: Use spread syntax when supported on all platforms, e.g. `bytes =
    // hashfunc([...namespace, ... value])`


    let bytes = new Uint8Array(16 + value.length);
    bytes.set(namespace);
    bytes.set(value, namespace.length);
    bytes = hashfunc(bytes);
    bytes[6] = bytes[6] & 0x0f | version;
    bytes[8] = bytes[8] & 0x3f | 0x80;

    if (buf) {
      offset = offset || 0;

      for (let i = 0; i < 16; ++i) {
        buf[offset + i] = bytes[i];
      }

      return buf;
    }

    return (0, _stringify.default)(bytes);
  } // Function#name is not settable on some platforms (#270)


  try {
    generateUUID.name = name; // eslint-disable-next-line no-empty
  } catch (err) {} // For CommonJS default export support


  generateUUID.DNS = DNS;
  generateUUID.URL = URL;
  return generateUUID;
}

},{"./parse.js":158,"./stringify.js":162}],166:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _rng = _interopRequireDefault(require("./rng.js"));

var _stringify = _interopRequireDefault(require("./stringify.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function v4(options, buf, offset) {
  options = options || {};

  const rnds = options.random || (options.rng || _rng.default)(); // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`


  rnds[6] = rnds[6] & 0x0f | 0x40;
  rnds[8] = rnds[8] & 0x3f | 0x80; // Copy bytes to buffer, if provided

  if (buf) {
    offset = offset || 0;

    for (let i = 0; i < 16; ++i) {
      buf[offset + i] = rnds[i];
    }

    return buf;
  }

  return (0, _stringify.default)(rnds);
}

var _default = v4;
exports.default = _default;
},{"./rng.js":160,"./stringify.js":162}],167:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _v = _interopRequireDefault(require("./v35.js"));

var _sha = _interopRequireDefault(require("./sha1.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const v5 = (0, _v.default)('v5', 0x50, _sha.default);
var _default = v5;
exports.default = _default;
},{"./sha1.js":161,"./v35.js":165}],168:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _regex = _interopRequireDefault(require("./regex.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function validate(uuid) {
  return typeof uuid === 'string' && _regex.default.test(uuid);
}

var _default = validate;
exports.default = _default;
},{"./regex.js":159}],169:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _validate = _interopRequireDefault(require("./validate.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function version(uuid) {
  if (!(0, _validate.default)(uuid)) {
    throw TypeError('Invalid UUID');
  }

  return parseInt(uuid.substr(14, 1), 16);
}

var _default = version;
exports.default = _default;
},{"./validate.js":168}],170:[function(require,module,exports){
(function (global){(function (){
const solidAuthn = require('@inrupt/solid-client-authn-browser');
const n3 = require('n3');
global.window.solidAuthn = solidAuthn;
global.window.n3 = n3;

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"@inrupt/solid-client-authn-browser":9,"n3":134}]},{},[170]);
