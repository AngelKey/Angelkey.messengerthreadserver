
bhs    = require 'base-http-server'
Base   = bhs.sct.SelfCertifiedToken
mm     = bhs.mod.mgr
idmod  = bhs.id
sc     = bhs.status.codes

{unix_time} = require('iced-utils').util

#=============================================================================

exports.config = config = ({gen}) ->
  cfg = 
    lifetime : mm.config.security.sct.lifetime
    key : mm.config.secrets.sct_key
    klass : SelfCertifiedToken
  if gen
    cfg.id = idmod.generate mm.config.id.sct 
  return cfg

#=============================================================================

exports.generate = (cb) ->
  cfg = config { gen : true }
  tok = new SelfCertifiedToken { cfg } 
  await tok.generate_to_client defer err, out
  cb err, out

#=============================================================================

exports.check = (raw, cb) ->
  cfg = config { gen : false }
  await SelfCertifiedToken.check_from_client raw, cfg, defer err, obj
  cb err, obj

#=============================================================================

class SelfCertifiedToken extends Base

  check_replay : (cb) ->
    q = "INSERT INTO used_challenge_tokens (token_id, ctime) VALUES(?,?)"
    args = [ @id, unix_time() ]
    await mm.db.update1 q, args, defer err
    err.code = sc.SCT_REPLAY if err?
    cb err

#=============================================================================
