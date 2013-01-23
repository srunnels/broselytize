
global systems_seen: table[addr,port,string] of time;

event new_connection(c: connection)
	{
    local rfc1918_subnets: set[subnet] = set(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16);
    when ( local host = lookup_addr(c$id$resp_h) )
        {
        if ( host == "<???>" )
            {
            for ( snet in rfc1918_subnets )
                {
                if ( c$id$resp_h in snet )
                    {
                    host = "RFC1918";
                    }
                }
            }
        systems_seen[c$id$resp_h, c$id$resp_p, host] = network_time(); 
        }
	}

event bro_done()
    {
    for ( [i,j,k] in systems_seen )
        {
        print fmt("Saw endpoint %s with address %s communicating on %s on %s", k, i, j, strftime("%Y/%m/%d - %H:%M:%S", systems_seen[i,j,k]));
        } 
    }
