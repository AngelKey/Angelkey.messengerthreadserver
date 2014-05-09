
bhs                   = require 'base-http-server'
{Handler,GET,POST}    = bhs.base
{api_route}           = require '../lib/urls'
sct                   = require '../lib/sct'
mm                    = bhs.mod.mgr

#=============================================================================

class GetChallengeHandler extends Handler

  _handle : (cb) ->
    await sct.generate defer err, challenge_token
    unless err?
      @pub { challenge_token }
      @pub mm.config.security.challenge
    cb err

#=============================================================================

class InitHandler extends Handler

  needed_fields : -> [ "challenge_token", "challenge_response" ]
  _handle : (cb) ->
    cb null

#=============================================================================

exports.bind_to_app = (app) ->
  GetChallengeHandler.bind app, api_route("challenge"), GET
  InitHandler.bind         app, api_route("init"), POST

#=============================================================================

