bhs                       = require 'keybase-http-server'
{Handler,GET,POST}        = bhs.base
sc                        = bhs.status.codes
log                       = bhs.log
{api_route}               = require '../lib/urls'
challenge                 = require '../lib/challenge'
mm                        = bhs.mod.mgr
DbTx                      = bhs.mod.db
{checkers,arr_subchecker} = require 'keybase-bjson-core'
{make_esc}                = require 'iced-error'
{bufeq_secure,dict_merge,unix_time} = require('iced-utils').util
kbmc                      = require('keybase-messenger-core')
idcheckers                = kbmc.id.checkers
{Cipher}                  = kbmc

#=============================================================================

H = (x) -> x.toString 'hex'
G = (y) -> new Buffer y, 'hex'

#=============================================================================

class Base extends Handler

  #---------------

  input_template : -> {
    i : idcheckers.thread
    t : idcheckers.write_token
    sender_zid : checkers.nnint
  }

  #---------------

  _handle_auth : (cb) ->
    q = "SELECT write_token FROM thread_keys WHERE thread_id=? AND user_zid=?"
    args = [ H(@input.i), @input.sender_zid ]
    await mm.db.load1 q, args, defer err, row
    if err? then # noop
    else if not bufeq_secure G(row.write_token), @input.write_token
      err = new Error "permission denied: bad write token"
      err.sc = sc.PERMISSION_DENIED
    cb err

#=============================================================================

class PostHeaderHandler extends Base

  input_template : -> dict_merge super(), {
    etime : checkers.nnint
    prev_msg_zid : checkers.nnint
    num_chunks : checkers.pint
  }

#=============================================================================

exports.bind_to_app = (app) ->
  PostHeaderHandler.bind app, api_route("msg/header"), POST

#=============================================================================

