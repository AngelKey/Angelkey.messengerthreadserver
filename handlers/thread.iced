
bhs                   = require 'base-http-server'
{Handler,GET,POST}    = bhs.base
{api_route}           = require '../lib/urls'
sct                   = require '../lib/sct'
mm                    = bhs.mod.mgr
{check_string}        = bhs.checkers.curried

#=============================================================================

class GetChallengeHandler extends Handler

  _handle : (cb) ->
    await sct.generate defer err, token
    unless err?
      @pub { challenge : { token } }
      @pub mm.config.security.challenge
    cb err

#=============================================================================

class InitHandler extends Handler

  needed_inputs : -> {
    "challenge.token"    : { checker : check_string(2)  } 
    "challenge.solution" : { checker : check_string(10) }
  }
  _handle : (cb) ->
    cb null

#=============================================================================

exports.bind_to_app = (app) ->
  GetChallengeHandler.bind app, api_route("challenge"), GET
  InitHandler.bind         app, api_route("init"), POST

#=============================================================================

