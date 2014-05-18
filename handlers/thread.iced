
bhs                   = require 'base-http-server'
{Handler,GET,POST}    = bhs.base
{api_route}           = require '../lib/urls'
sct                   = require '../lib/sct'
mm                    = bhs.mod.mgr
{check_string}        = bhs.checkers.curried

#=============================================================================

class GetSessionChallengeHandler extends Handler

  _handle : (cb) ->
    await sct.generate defer err, token
    unless err?
      cfg = mm.config.security.challenge
      @pub { 
        challenge : { 
          token : token,
          params : {
            bytes : cfg.bytes
            less_than : new Buffer(cfg.less_than, 'hex')
          }
        }
      }
    cb err

#=============================================================================

class SessionInitHandler extends Handler

  needed_inputs : -> {
    "challenge.token"    : { checker : check_array(4) }
    "challenge.solution" : { checker : check_buffer(1) }
  }
  _handle : (cb) ->
    cb null

#=============================================================================

exports.bind_to_app = (app) ->
  GetSessionChallengeHandler.bind app, api_route("session/challenge"), GET
  SessionInitHandler.bind         app, api_route("session/init"), POST

#=============================================================================

