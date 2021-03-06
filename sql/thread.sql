
CREATE TABLE `used_challenge_tokens` (
	`token_id` CHAR(32) NOT NULL PRIMARY KEY,
	`ctime` BIGINT UNSIGNED NOT NULL,
	`atime` BIGINT UNSIGNED NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `threads` (
	thread_id CHAR(64) NOT NULL PRIMARY KEY,       --- at least one for each group of conversants
	num_conversants INT(11) UNSIGNED NOT NULL      --- the # of conversants in the conversation
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `thread_keys` (
	thread_id CHAR(64) NOT NULL,                   --- at least one for each group of conversants
	user_zid INT(11) UNSIGNED NOT NULL,            --- #0, #1, #2, etc. lowest UID gets 0.
	key_data TEXT NOT NULL,                        --- Armor64-ed PGP message
	etime BIGINT UNSIGNED NOT NULL,                --- When to delete the key
	write_token CHAR(64) NOT NULL,                 --- conversants need to prove knowledge of this key to write
	signing_key_public BLOB,                       --- temporary signing key	
	key_proof TEXT,                                --- Proof of that key with their main public key
	signing_key_private TEXT,                      --- encrypted version of the signing key
	PRIMARY KEY (`thread_id`, `user_zid`),
	CONSTRAINT `thread_keys_ibfk_1` FOREIGN KEY(`thread_id`) REFERENCES `threads` (`thread_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `messages` (
	thread_id CHAR(64) NOT NULL,                   --- at least one for each group of conversants
	msg_zid INT(11) UNSIGNED NOT NULL,             --- The sequence number in the msg_bodies table
	sender_zid INT(11) UNSIGNED NOT NULL,          --- #0, #1, etc... who the sender was
	num_chunks INT(11) UNSIGNED NOT NULL,          --- the number of chunks in the mesasge (usually 1)
	etime BIGINT UNSIGNED NOT NULL,                --- When to delete the message
	sig TEXT,                                      --- optional signature by the author
	prev_msg_zid INT(11) UNSIGNED NOT NULL,        --- the last zid this client got
	parent_msg_zid INT(11) UNSIGNED NOT NULL,      --- Parent MSG for atachments, or 0 for not parent
	PRIMARY KEY (`thread_id`, `msg_zid`),
	CONSTRAINT `messages_ibfk_1` FOREIGN KEY(`thread_id`) REFERENCES `threads` (`thread_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `chunks` (
    thread_id CHAR(64) NOT NULL,                   --- Thread ID
    msg_zid INT(11) UNSIGNED NOT NULL,             --- MSG id integer sequence number in that thread
    chunk_zid INT(11) UNSIGNED NOT NULL,           --- chunk id integer sequence number in that message
    data MEDIUMBLOB NOT NULL,                      --- Encrypted data.
    PRIMARY KEY (`thread_id`, `msg_zid`, `chunk_zid`),
    CONSTRAINT `chunks_ibfk_1` FOREIGN KEY(`thread_id`, `msg_zid`) REFERENCES `messages` (`thread_id`, `msg_zid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `deletions` (
    thread_id CHAR(64) NOT NULL,                     --- Thread ID
    user_zid INT(11) UNSIGNED NOT NULL,              --- The user who deleted
    msg_zid INT(11) UNSIGNED NOT NULL,               --- Which message s/he deleted at
    PRIMARY KEY (`thread_id`, `user_zid`,`msg_zid`), --- Can have multiple deletions for partial orders
    CONSTRAINT `deletions_ibkf_1` FOREIGN KEY(`thread_id`, `user_zid`) REFERENCES `thread_keys` (`thread_id`, `user_zid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
