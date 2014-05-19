
bhs                   = require 'base-http-server'
Base                  = bhs.sct.SelfCertifiedToken
mm                    = bhs.mod.mgr
idmod                 = bhs.id
sc                    = bhs.status.codes
triplesec             = require 'triplesec'
{WordArray,scrypt}    = triplesec
{buffer_cmp_ule}      = triplesec.util
{unix_time}           = require('iced-utils').util

#=============================================================================

exports.config = config = ({gen, solution}) ->
  cfg = 
    lifetime : mm.config.security.sct.lifetime
    key : mm.config.secrets.sct_key
    klass : ChallengeToken
    solution : solution
  if gen
    cfg.id = idmod.generate mm.config.id.sct 
  return cfg

#=============================================================================

exports.generate = (cb) ->
  cfg = config { gen : true }
  tok = new ChallengeToken { cfg } 
  await tok.generate defer err, out
  cb err, out

#=============================================================================

exports.check = ({token, solution}, cb) ->
  cfg = config { gen : false, solution }
  await ChallengeToken.check_from_client token, cfg, defer err, obj
  cb err, obj

#=============================================================================

class ChallengeToken extends Base

  #-----------------

  constructor : (args) ->
    super args
    @solution = args.cfg?.solution

  #-----------------

  check_solution : (cb) ->
    cfg = mm.config.security.challenge
    err = null
    args = 
      N : cfg.N
      p : cfg.p
      r : cfg.r
      salt : WordArray.from_buffer @solution
      key : WordArray.from_buffer @id
      dkLen : cfg.bytes
    await scrypt args, defer wa
    target = new Buffer cfg.less_than, 'hex'
    sol = wa.to_buffer()
    if buffer_cmp_ule(sol,target) >= 0
      err = new Error "solution failed"
      err.code = sc.SCT_BAD_SOLUTION
    cb err

  #-----------------

  check_replay : (cb) ->
    q = "INSERT INTO used_challenge_tokens (token_id, ctime) VALUES(?,?)"
    args = [ @id.toString('hex'), unix_time() ]
    await mm.db.update1 q, args, defer err
    err.code = sc.SCT_REPLAY if err?
    cb err

#=============================================================================
