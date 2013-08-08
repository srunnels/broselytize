# Sample of extending the Intel Framework to handle the X-Forwarded-For header.

export {
    # include a custom Intel::Where type if one doesn't already exist in
    # intel/where-locations.bro
    redef enum Intel::Where += {
        HTTP::IN_X_FORWARDED_FOR
    };
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( is_orig && name == "X-FORWARDED-FOR" )
        {
		Intel::seen([$host=to_addr(value),            
		             $indicator_type=Intel::ADDR, 
		             $conn=c,
		             $where=HTTP::IN_X_FORWARDED_FOR]);
        }
	}
