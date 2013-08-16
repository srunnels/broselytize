@load base/frameworks/notice
@load base/utils/site
@load base/protocols/dns

global notices: table[Notice::Type] of set[string];

# Turn on UDP content delivery.
redef udp_content_deliver_all_resp = T &redef;
redef udp_content_deliver_all_orig = T &redef;

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
    print fmt("%s: %s", name, value);
	}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
    print fmt("%s.%d-%s.%d: %s %s", c$id$resp_h, c$id$resp_p, c$id$orig_h, c$id$orig_p, code, reason);
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
    print fmt("%s", data);
	}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
    print fmt("%s.%d-%s.%d: %s %s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, method, original_URI);
	}

event udp_contents(u: connection, is_orig: bool, contents: string)
	{
    if (is_orig)
        {
        print fmt("%s.%d-%s.%d:", u$id$orig_h, u$id$orig_p, u$id$resp_h, u$id$resp_p);
        }
    else
        {
        print fmt("%s.%d-%s.%d:", u$id$resp_h, u$id$resp_p, u$id$orig_h, u$id$orig_p);
        }
    print fmt("%s",contents);
	}

event DNS::log_dns(rec: DNS::Info)
    {
    print("--------- DNS Log -----------");
    if (rec?$query)
        {
        print(fmt("Query: %s", rec$query));
        }
    if (rec?$answers)
        {
        print(fmt("Answer(s): %s", rec$answers));
        }
    }

event bro_done()
    {
    print("------ Notices Raised -------");
    print notices;

    }
    
event Notice::log_notice(rec: Notice::Info)
    {
    local curr_set: set[string];
    if (rec$note in notices)
        {
        curr_set = notices[rec$note];
        }
    add curr_set[rec$msg];
    notices[rec$note] = curr_set;
    }
