import url from 'url';
import { format } from 'util';
import { Strategy } from 'passport-strategy';
import { Client } from 'openid-client';

function verified(err, user, info = {}) {
  if (err) {
    this.error(err);
  } else if (!user) {
    this.fail(info);
  } else {
    this.success(user, info);
  }
}
type TOpenIDConnectStrategyArgs = { client: any; params?: any; passReqToCallback?: boolean; sessionKey?: string; usePKCE?: boolean | string; extras?: any };

/**
 * @name constructor
 * @api public
 */
export class OpenIDConnectStrategy extends Strategy {
  name = 'oidc';
  _client: any;
  _issuer: any;
  _verify: any;
  _passReqToCallback: boolean;
  _usePKCE: boolean | string;
  _key: string;
  _params: any;
  _extras: any;

  constructor({ client, params = {}, passReqToCallback = false, sessionKey, usePKCE = true, extras = {} }: TOpenIDConnectStrategyArgs, verify) {
    super();

    if (!client || typeof client !== 'object') {
      throw new TypeError('client must be an instance of openid-client Client');
    }

    if (typeof verify !== 'function') {
      throw new TypeError('verify callback must be a function');
    }

    if (!client.issuer || !client.issuer.issuer) {
      throw new TypeError('client must have an issuer with an identifier');
    }

    this._client = client;
    this._issuer = client.issuer;
    this._verify = verify;
    this._passReqToCallback = passReqToCallback;
    this._usePKCE = usePKCE;
    this._key = sessionKey || `oidc:${url.parse(this._issuer.issuer).hostname}`;
    this._params = Object.assign({}, params);
    this._extras = Object.assign({}, extras);

    if (!this._params.response_type) this._params.response_type = 'code';
    if (!this._params.redirect_uri) this._params.redirect_uri = client.redirect_uris && client.redirect_uris[0];
    if (!this._params.scope) this._params.scope = 'openid';

    if (this._usePKCE === true) {
      const supportedMethods = Array.isArray(this._issuer.code_challenge_methods_supported) ? this._issuer.code_challenge_methods_supported : false;

      if (supportedMethods && supportedMethods.includes('S256')) {
        this._usePKCE = 'S256';
      } else if (supportedMethods && supportedMethods.includes('plain')) {
        this._usePKCE = 'plain';
      } else if (supportedMethods) {
        throw new TypeError('neither code_challenge_method supported by the client is supported by the issuer');
      } else {
        this._usePKCE = 'S256';
      }
    } else if (typeof this._usePKCE === 'string' && !['plain', 'S256'].includes(this._usePKCE)) {
      throw new TypeError(`${this._usePKCE} is not valid/implemented PKCE code_challenge_method`);
    }

    this.name = url.parse(client.issuer.issuer).hostname || 'oidc';
  }

  authenticate(req, options) {
    (async () => {
      const client = this._client;
      if (!req.session) {
        throw new TypeError('authentication requires session support');
      }
      const reqParams = client.callbackParams(req);
      const sessionKey = this._key;

      /* start authentication request */
      if (Object.keys(reqParams).length === 0) {
        // provide options object with extra authentication parameters
        const params = {
          state: this.generateState(),
          ...this._params,
          ...options,
        };

        if (!params.nonce && params.response_type.includes('id_token')) {
          params.nonce = this.generateState();
        }

        req.session[sessionKey] = this.pick(params, 'nonce', 'state', 'max_age', 'response_type');

        if (this._usePKCE && params.response_type.includes('code')) {
          const verifier = this.generateState();
          req.session[sessionKey].code_verifier = verifier;

          switch (this._usePKCE) {
            case 'S256':
              params.code_challenge = this.codeChallenge(verifier);
              params.code_challenge_method = 'S256';
              break;
            case 'plain':
              params.code_challenge = verifier;
              break;
          }
        }

        //save the authentication request parameters
        req.session.reqParams = params;

        this.redirect(client.authorizationUrl(params));
        return;
      }
      /* end authentication request */

      /* start authentication response */

      const session = req.session[sessionKey];
      if (Object.keys(session || {}).length === 0) {
        throw new Error(format('did not find expected authorization request details in session, req.session["%s"] is %j', sessionKey, session));
      }

      const { state, nonce, max_age: maxAge, code_verifier: codeVerifier, response_type: responseType } = session;

      try {
        delete req.session[sessionKey];
      } catch (err) { }

      const opts = {
        redirect_uri: this._params.redirect_uri,
        ...options,
      };

      const checks = {
        state,
        nonce,
        max_age: maxAge,
        code_verifier: codeVerifier,
        response_type: responseType,
      };

      const tokenset = await client.callback(opts.redirect_uri, reqParams, checks, this._extras);

      const passReq = this._passReqToCallback;
      const loadUserinfo = this._verify.length > (passReq ? 3 : 2) && client.issuer.userinfo_endpoint;

      const args = [tokenset, verified.bind(this)];

      if (loadUserinfo) {
        if (!tokenset.access_token) {
          throw new Error('expected access_token to be returned when asking for userinfo in verify callback');
        }
        const userinfo = await client.userinfo(tokenset);
        args.splice(1, 0, userinfo);
      }

      if (passReq) {
        args.unshift(req);
      }

      this._verify(...args);
      /* end authentication response */
    })().catch((error) => {
      this.fail(error);
    });
  }

  // Helper methods
  generateState() {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  }

  pick(obj, ...keys) {
    const result = {};
    keys.forEach(key => {
      if (obj.hasOwnProperty(key)) {
        result[key] = obj[key];
      }
    });
    return result;
  }

  codeChallenge(verifier) {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(verifier).digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
}
