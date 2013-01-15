# Can we log Youtube titles?
# We can get the first title, but HTTP is stream based and Bro sees it as such.  

global title_table: table[string] of string;

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
 	{
    if ( is_orig )
        {
        return;
        }
            
    if (/\.youtube\.com$/ in c$http$host && /^\/watch/ in c$http$uri)
        {
        if (c$uid !in title_table)
            {
            title_table[c$uid] = data;
            }
        else
            if ( |title_table[c$uid]| < 2000 )
                {
                title_table[c$uid] = cat(title_table[c$uid], data);
                }
            }
        }


event bro_done()
    {
    for ( i in title_table )
        {
        if ( /\<title\>/ in title_table[i] )
            {
            local temp: table[count] of string;
            temp = split(title_table[i], /\<\/?title\>/);
            if ( 2 in temp )
                {
                print temp[2];
                }
            }
        }
    }