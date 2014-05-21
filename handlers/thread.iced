
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
{unix_time}                = require('iced-utils').util

#=============================================================================

H = (x) -> x.toString('hex')

#=============================================================================

class InitThreadHandler extends Handler

  input_template : -> {
    session_id : checkers.buffer(4)   # valid session ID
    i : checkers.buffer(8)            # the thread ID
    etime : checkers.intval()
    users : checkers.array {
      min : 2, 
      checker : arr_subchecker {
        t : checkers.buffer(8)        # the write token
        ctext : checkers.string(10)   # the encrypted bundle for the user
      }
    }
  }

  #----------------

  validate_session : (cb) ->
    now = unix_time()
    token_id = H(@input.session_id)
    q = "SELECT ctime FROM used_challenge_tokens WHERE token_id = ?"
    args = [ token_id ]
    await mm.db.load1 q, args, defer err, row
    if not err? and (exp = (now - row.ctime - mm.config.security.session.lifetime)) > 0
      err = new Error "Session expired #{exp}s ago"
      err.code = sc.SESSION_EXPIRED
    else if not err?
      q = "UPDATE used_challenge_tokens SET atime=? WHERE token_id=?"
      args = [ now, token_id ]
      await mm.db.update1 q, args, defer err
      log.error "Failed to update session: #{err.message}" if err?
    cb err

  #----------------

  write : (cb) ->
    dbtx = mm.db.new_tx()

    q = "INSERT INTO threads(`thread_id`, `num_conversants`) VALUES(?,?)"
    args = [ H(@input.i), @input.users.length ]
    dbtx.push q, args

    for u,i in @input.users
      q = """INSERT INTO thread_keys (thread_id, user_zid, key_data, write_key, etime)
             VALUES(?,?,?,?,?)
          """
      args = [ H(@input.i), i, u.ctext, H(u.t), @input.etime ]
      dbtx.push q, args

    await mm.db.transaction dbtx, defer err
    cb err

  #----------------

  _handle : (cb) ->
    esc = make_esc cb, "InitThreadHandler::_handle"
    await @validate_session esc defer()
    await @write esc defer()
    cb null

#=============================================================================

exports.bind_to_app = (app) ->
  InitThreadHandler.bind app, api_route("thread/init"), POST

#=============================================================================

