
{constants} = require './constants'

##=================================================================================

exports.api_route = (base) ->
  new RegExp "/api/#{constants.api.CURRENT_VERSION}/#{base}\\.(json|msgpack|msgpack64)"

##=================================================================================

