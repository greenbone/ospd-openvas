if(description)
{
  script_dependencies("keys.nasl");
  script_oid("1.3.6.1.4.1.25623.1.0.90022");
  script_version("2019-11-10T15:30:28+0000");
  script_name("mqtt test");
  script_category(ACT_INIT);
  script_family("my test family");  
  script_tag(name:"some", value:"tag");
  script_tag(name:"last_modification", value:"2019-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2015-03-27 12:00:00 +0100 (Fri, 27 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"qod", value:"0");

  script_version("2021-08-19T02:25:52+0000");
  script_cve_id("CVE-0000-0000", "CVE-0000-0001");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-07 19:36:00 +0000 (Fri, 07 Aug 2020)");
  script_xref(name:"Example", value:"GB-Test-1");
  script_xref(name:"URL", value:"https://www.greenbone.net");


  script_add_preference(name:"example", type:"entry", value:"a default string value");

  script_tag(name:"vuldetect", value:"Describes what this plugin is doing to detect a vulnerability.");

  script_tag(name:"summary", value:"A short description of the problem");
  script_tag(name:"insight", value:"Some detailed insights of the problem");
  script_tag(name:"impact", value:"Some detailed about what is impacted");

  script_mandatory_keys("test/key1");
  script_require_keys("test/key2");
  script_exclude_keys("1", "2");
  script_tag(name:"affected", value:"Affected programs, operation system, ...");

  script_tag(name:"solution", value:"Solution description");
  script_tag(name:"solution_type", value:"Type of solution (e.g. mitigation, vendor fix)");
  script_tag(name:"solution_method", value:"how to solve it (e.g. debian apt upgrade)");
  script_tag(name:"qod_type", value:"package");
exit(0);
}

set_kb_item( name: "test", value: TRUE );

sec_msg = "this is a security message";
log_msg = "this is a log message";
err_msg = "this is a error message";

security_message(data:sec_msg);
log_message(data:log_msg);
error_message(data:err_msg);

exit(0);
