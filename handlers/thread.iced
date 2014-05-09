
bhs                   = require 'base-http-server'
{Handler,GET,POST}    = bhs.base
{api_route}           = require '../lib/urls'
sct                   = require '../lib/sct'

#=============================================================================

class GetChallengeHandler extends Handler

  _handle : (cb) ->
    await sct.generate defer err, token
    @pub { token } unless err?
    cb err

#=============================================================================

exports.bind_to_app = (app) ->
  GetChallengeHandler.bind app, api_route("challenge"), GET

#=============================================================================

