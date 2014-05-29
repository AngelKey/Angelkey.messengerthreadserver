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
pgpchecker                = kbmc.pgp.checker
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
    else if not bufeq_secure G(row.write_token), @input.t
      err = new Error "permission denied: bad write token"
      err.sc = sc.PERMISSION_DENIED
    cb err

#=============================================================================

class PostHeaderHandler extends Base

  #-----------------------

  input_template : -> dict_merge super(), {
    etime : checkers.nnint
    prev_msg_zid : checkers.nnint
    num_chunks : checkers.pint
    parent_msg_zid : checkers.nnint
  }

  #-----------------------

  _handle : (cb) ->
    go = true
    esc = make_esc cb, "PostHeaderHandler::_handle"
    await @insert_loop esc defer()
    @pub { @msg_zid }
    cb null

  #-----------------------

  insert_loop : (cb) ->
    err = null
    go = true
    while go
      await @insert defer err
      if not err? then go = false
      else if err.code in [ 'ER_DUP_KEY', 'ER_DUP_ENTRY' ] 
        await setTimeout defer(), 1
      else
        go = false
    cb err

  #-----------------------

  insert : (cb) -> 
    esc = make_esc cb, 'PostHeaderHandler::_handle::ins'
    q = "SELECT MAX(msg_zid) as m FROM messages WHERE thread_id=?"
    args = [ H(@input.i) ]
    await mm.db.load1 q, args, esc defer row
    @msg_zid = (row.m or 0) + 1
    q = """INSERT INTO messages
             (thread_id, msg_zid, sender_zid, num_chunks, etime, prev_msg_zid, parent_msg_zid)
            VALUES(?,?,?,?,?,?,?)"""
    args = [ H(@input.i), @msg_zid, @input.sender_zid, 
             @input.num_chunks, @input.etime, @input.prev_msg_zid, @input.parent_msg_zid]
    await mm.db.update1 q, args, esc defer()
    cb null

#=============================================================================

class PostChunkHandler extends Base

  input_template : -> dict_merge super(), {
    chunk_zid : checkers.nnint
    msg_zid : checkers.nnint
    ctext : Cipher.checker
  }

  #-----------------

  _handle : (cb) ->
    q = "INSERT INTO chunks (thread_id, msg_zid, chunk_zid, data) VALUES(?,?,?,FROM_BASE64(?))"
    args = [ H(@input.i), @input.msg_zid, @input.chunk_zid, Cipher.encode_to_db(@input.ctextechunk) ]
    await mm.db.update1 q, args, defer err
    cb err

#=============================================================================

class PostSigHandler extends Base

  input_template : -> dict_merge super(), {
    sig : pgpchecker()
    msg_zid : checkers.nnint
  }

  #-----

  _handle : (cb) ->
    q = "UPDATE messages SET sig=? WHERE thread_id=? and msg_zid=? and sender_zid=?"
    args = [ @input.sig, H(@input.i), @input.msg_zid, @input.sender_zid ]
    await mm.db.update1 q, args, defer err
    cb err

#=============================================================================

exports.bind_to_app = (app) ->
  PostHeaderHandler.bind app, api_route("msg/header"), POST
  PostChunkHandler.bind app, api_route("msg/chunk"), POST
  PostSigHandler.bind app, api_route("msg/sig"), POST

#=============================================================================

