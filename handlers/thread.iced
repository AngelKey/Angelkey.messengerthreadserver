
bhs                   = require 'keybase-http-server'
{Handler,GET,POST}    = bhs.base
{api_route}           = require '../lib/urls'
challenge             = require '../lib/challenge'
mm                    = bhs.mod.mgr
{checkers}            = require 'keybase-bjson-core'
{make_esc}            = require 'iced-error'

#=============================================================================

class InitThreadHandler extends Handler

  input_template : -> {
    session_id : checkers.buffer(4)   # valid session ID
    i : checkers.buffer(8)            # the thread ID
    users : checkers.array(2)         # 2 or more users
  }

  #----------------

  validate_session : (cb) ->
    q = "SELECT ctime FROM used_challenge_tokens WHERE token_id = ?"
    args = [ @input.session_id.toString('hex') ]
    cb null

  #----------------

  _handle : (cb) ->
    esc = make_esc cb, "InitThreadHandler::_handle"
    await @validate_session esc defer()
    cb err

#=============================================================================

exports.bind_to_app = (app) ->
  InitThreadHandler.bind app, api_route("thread/init"), GET

#=============================================================================

