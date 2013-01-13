
global title_set: set[string];

event http_reply(c: connection, version: string, code: count, reason: string)
	{
    if ( /youtube.com/ in c$http$host && c$http$method == "GET" && /^\/watch\?v=/ in c$http$uri )
        {
        add title_set[c$uid];
        }
	}
    

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
 	{
    if (is_orig)
        {
        return;
        }

    if (c$uid in title_set )
        {
                
        if (/\<title\>/ in data && /\<\/title\>/ in data)
            {
            local temp: table[count] of string;
            temp = split(data, /\<title\>/);
            temp = split(temp[2], /\<\/title\>/);
            print fmt("%s - %s %s: %s", c$http$method, c$http$host, c$http$uri, temp[1]);
            delete title_set[c$uid];
            }
        }
    }
