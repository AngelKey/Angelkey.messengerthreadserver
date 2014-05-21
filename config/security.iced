
exports.config = 
  sct :
    lifetime : 60*5
  challenge : 
    bytes : 2
    N : (1 << 10)
    r : 8
    p : 1
    less_than : "0010"
  session:
    lifetime : 60
