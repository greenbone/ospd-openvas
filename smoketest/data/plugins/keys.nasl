if(description)
{
  script_oid("1.3.6.1.4.1.25623.0.0.1");
  script_tag(name:"last_modification", value:"2019-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2015-03-27 12:00:00 +0100 (Fri, 27 Mar 2015)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("keys");
  script_family("my test family");  

  exit(0);
}

set_kb_item( name: "test/key1", value: TRUE );
set_kb_item( name: "test/key2", value: 42 );
set_kb_item( name: "test/key3", value: "waldfee" );
