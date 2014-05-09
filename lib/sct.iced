
bhs    = require 'base-http-server'
Base   = bhs.sct.SelfCertifyingToken
mm     = bhs.mod.mgr
idmod  = bhs.id
sc     = bhs.status.codes

{unix_time} = require('iced-utils').util

#=============================================================================

exports.config = config = ({gen}) ->
  cfg = 
    lifeftime : mm.config.security.sct.lifetime
    key : mm.config.secrets.sct_key
    klass : SelfCertifyingToken
  if gen
    cfg.id = idmod.generate mm.config.id.sct 
  return cfg

#=============================================================================

exports.generate = (cb) ->
  tok = new SelfCertifyingToken config {gen : true }
  await tok.generate_to_client defer err, out
  cb err, out

#=============================================================================

export.check = (raw, cb) ->
  cfg = config { gen : false }
  await SelfCertifyingToken.check_from_client raw, cfg, defer err, obj
  cb err, obj

#=============================================================================

class SelfCertifyingToken extends Base

  check_replay : (cb) ->
    q = "INSERT INTO used_challenge_tokens (token_id, ctime) VALUES(?,?)"
    args = [ @id, unix_time() ]
    await mm.db.update1 q, args, defer err
    err.code = sc.SCT_REPLAY if err?
    cb err

#=============================================================================
