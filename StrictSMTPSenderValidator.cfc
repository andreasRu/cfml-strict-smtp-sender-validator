<cfscript>
/**
 * @hint "Strict SMTP Verifier" verifies if an IPv4 address is allowed to send an email on 
 * behalf of an email address (e.g. someaddress@emaildomain.com ) or an email domain (e.g. @emaildomain.com).
 * This component doesn't follow all SPF rules as of https://tools.ietf.org/html/rfc7208 and uses a very strict approach
 * like many top email providers do. Caution: IPv6 is NOT SUPPORTED!
 * Created by https://github.com/andreasRu 
 **/
component {

	property 	name="debugLog" type="string";
	property 	name="debugLogLevel" type="number";
	property 	name="resultSMTPVerifier" type="struct"; 
	
	/**
	 * Constructor for SMTP Verifier with debugging possibility 
	 */
	public struct function init( number debugLogLevel=0 ){

		this.debugLog = "";
		this.debugLogLevel = arguments.debugLogLevel;
		this.resultSMTPVerifier= {};

		if( this.debugLogLevel > 0 ) {
				appendDebugLogLine( "Component SMTPverifier initialized" ); 
			} 
		
		verifyAndInstallDependencies();

		return this;
	}

	/**
	 * Debug logging function 
	 */
	private void function appendDebugLogLine(required string logtext ) {
		if( this.debugLogLevel > 0 ){
			this.debugLog = this.debugLog & arguments.logtext & ";<br>" 
		}

	}


	/**
	 * @hint Verify if the dependencies are installed/loaded. If not loaded, it calls dependenciesJarOSGIinstall()
	 */
	private void function verifyAndInstallDependencies(){

		// Check OSGI dependencies "com.github.seancfoley.ipaddress"
		local.luceeOSGIutil = CreateObject( "java", "lucee.runtime.osgi.OSGiUtil" );
		local.osgiUtil=luceeOSGIutil.init();
		
		// get loaded bundle object if loaded
		local.bundle=local.osgiUtil.getBundleLoaded( JavaCast("string", "com.github.seancfoley.ipaddress") , local.osgiUtil.toVersion( "5.3.3" ), JavaCast( "null", "" ) );
		
		if( !IsNull( local.bundle ) ){
			appendDebugLogLine( "Dependency Bundle ""./jars/ipaddress-5.3.3.jar"" already LOADED. Skipping JAR install" ); 
			//local.bundle.uninstall();
		} else {
			appendDebugLogLine( "Dependency Bundle ""./jars/ipaddress-5.3.3.jar"" MISSING" ); 
			appendDebugLogLine( "Calling 'dependenciesJarOSGIinstall( ""./jars/ipaddress-5.3.3.jar"");'" ); 
			dependenciesJarOSGIinstall( "./jars/ipaddress-5.3.3.jar");
		}

	}


	/**
	 * @hint Jars Libary installer as shown by master and guru Brad Wood
	 * SEE https://wwvv.codersrevolution.com/blog/using-osgi-to-load-a-conflicting-jar-into-lucee-server 
	 */
	private void function dependenciesJarOSGIinstall( required string jarFilePhysicalLocation ) {

		CFMLEngine = createObject( "java", "lucee.loader.engine.CFMLEngineFactory" ).getInstance();
		OSGiUtil = createObject( "java", "lucee.runtime.osgi.OSGiUtil" );
		resource = CFMLEngine.getResourceUtil().toResourceExisting( getPageContext(), expandPath( arguments.jarFilePhysicalLocation ) );
		local.ipaddressBundle = OSGiUtil.installBundle( CFMLEngine.getBundleContext(), resource, true);
		// Assuming  
		appendDebugLogLine( "Dependency loaded: '#arguments.jarFilePhysicalLocation#'" );
				
	}


	/**
	 * @hint Returns true a specific SMTP server IP address is allowed to send an email on behalf of the emails address domain name.
	 */
	public struct function isSendersIPAllowedForEmailAddress(
		required string ipAddress,
		required string emailAddress,
		required string heloSMTPString="" ) {
			
			local.ipAddress = arguments.ipAddress;
			local.emailAddress = arguments.emailAddress;
			local.heloSMTPString = arguments.heloSMTPString;
			local.ipAddressOfDomainName = "";
			local.domainName= "";
	

			/**
			* 	mail Domain and Email Address Validation 
			*/
			
			appendDebugLogLine( "<hr><b>Start Validation for IP '#local.ipAddress#' for #local.emailAddress#</b>" );
				
			if ( left( local.emailAddress, 1 ) == "@" ){
				// Assuming Email Domain has only been specified 
				appendDebugLogLine( "Domain name #local.emailAddress# instead of email address submitted. Silently add fake inbox selector ""someaddress"" ( result: ""someaddress#local.emailAddress#"" )" );
				local.emailAddress = "someaddress" & local.emailAddress;

			};
				
			if( !isValid( "email", local.emailAddress ) ){
				
				appendDebugLogLine( "EmailAddress '#encodeforHTML(local.emailAddress)#' is syntatically not valid" );
				
				// break here and send component data
				this.resultSMTPVerifier[ "reason" ]="Email-address not valid";
				this.resultSMTPVerifier[ "result" ]= false;
				return this.resultSMTPVerifier;

			};

			




			// Continue validation	
			appendDebugLogLine( "Email address / email domain #encodeforHTML(local.emailAddress)# is syntatically correct. Continue verification" );
			local.domainName = listLast( local.emailAddress, "@" );
		







			/**
			* 	Static Whitelist Check
			*/
			appendDebugLogLine( "<hr><b>*** CHECK 1 Whitelists:</b> Verify if the senders IP  '#local.ipAddress#' is whitelisted");
			if( isIPAddressWhitelisted( local.ipAddress,  local.domainName ) ){
				
				appendDebugLogLine( "IP '#local.ipAddress#' IS statically whitelisted for @#local.domainName#" );
				this.resultSMTPVerifier[ "reason" ]= "Senders IP '#local.ipAddress#' is statically whitelisted for @#local.domainName#";
				this.resultSMTPVerifier[ "result" ]= true;
				return this.resultSMTPVerifier;

			} else {

				appendDebugLogLine( "Senders IP '#local.ipAddress#' is NOT Whitelisted" );
				//Don't break here

			};







			/**
			* 	DNS "A" Entry Check
			*/	
			appendDebugLogLine( "<hr><b>*** CHECK 2 DNS-A Entries:</b>  Verify if the senders IP #local.ipAddress# is the same as in 'A'-DNS-entry for '#local.domainName#'" );
			
			if( isSendersIPAllowedByA( local.ipAddress, local.domainName) is true ) {
				appendDebugLogLine( "Senders IP #local.ipAddress# equals #local.ipAddressOfDomainName# as specified in 'A'-DNS-entry for '#local.domainName#'" );
				this.resultSMTPVerifier[ "reason" ]= "Senders equals #local.ipAddressOfDomainName# as specified in 'A'-DNS-entry for '#local.domainName#'";
				this.resultSMTPVerifier[ "result" ]= true;
				return this.resultSMTPVerifier;
			} else {
				appendDebugLogLine( "SendersIP '#local.ipAddress#' doesn't correspond to A-Entry" );
				//Don't break here, because SMTP server IP still can differ from (e.g MX or SPF)
			};







			/**
			* 	DNS "MX" Entry Check
			*/	
			appendDebugLogLine( "<hr><b>*** CHECK 3 MX-Entries:</b> Verify if the senders IP #local.ipAddress# is the same IP as in 'MX'-DNS-entry by CALLING: isSendersIpAllowedByMX( '#local.ipAddress#'' , '#local.domainName#')" );
			
			if( isSendersIPAllowedByMX( local.ipAddress, local.domainName) is true ){
				appendDebugLogLine( "Senders IP #local.ipAddress# equals #local.ipAddressOfDomainName# as specified in 'MX'-DNS-entry for '#local.domainName#'" );
				this.resultSMTPVerifier[ "reason" ]= "Senders equals #local.ipAddressOfDomainName# as specified in 'MX'-DNS-entry for '#local.domainName#'";
				this.resultSMTPVerifier[ "result" ]= true;
				return this.resultSMTPVerifier;
			};







			/**
			* 	SPF Entry Check
			*/	
			appendDebugLogLine( "<hr><b>*** CHECK 6 SPF Entries:</b> Verify if Senders IP #local.ipAddress# is allowed to send Email on behalf of '#local.domainName#' by CALLING: isSendersIpAllowedBySPF( '#arguments.ipAddress#', '#domainName#'')" );
			if ( isSendersIpAllowedBySPF( local.ipAddress, local.domainName ) ) {
				appendDebugLogLine( "SPF: true" );
				this.resultSMTPVerifier[ "reason" ]= "SPFcheck for '#local.ipAddress#' OK";
				this.resultSMTPVerifier[ "result" ]= true;
				return this.resultSMTPVerifier;
			};







			/**
			* 	DNS "PTR" Entry Check come from same Domain
			*/	
			appendDebugLogLine( "<hr><b>*** CHECK 7 PTR-Entries:</b> Verify if the senders IP #local.ipAddress# 'PTR'-DNS-entry by CALLING: isSendersIpAllowedByPTR( '#local.ipAddress#' , '#local.domainName#')" );
			
			if( isSendersIPAllowedByPTR( local.ipAddress, local.domainName) is true ){
				
				appendDebugLogLine( "PTR '#listToArray( arguments.ipAddress, ".").reverse().toList(".")#.in-addr.arpa' has same domainpart of '#local.domainName#'" );
				this.resultSMTPVerifier[ "reason" ]= "Senders PTR '#listToArray( arguments.ipAddress, ".").reverse().toList(".")#.in-addr.arpa' is part of '#local.domainName#'";
				this.resultSMTPVerifier[ "result" ]= true;
				return this.resultSMTPVerifier;
		
			};







			/**
			* 	Resolve HELO if string has been submitted
			*/	
			appendDebugLogLine( "<hr><b>*** CHECK 8 EHLO:</b> Verify if Senders EHLO '#local.heloSMTPString#' resolves to an IP address" );
			if( len( trim( local.heloSMTPString ) ) ){
				
				if( hasSendersValidHelo( local.heloSMTPString ) ){

					appendDebugLogLine( "HELO STRING is valid" );
			

				} else {

					appendDebugLogLine( "HELO STRING is NOT valid" );
			
				};

			} else {

				appendDebugLogLine( "EHLO string was NOT specified. Check skipped" );
			};
			

		


		// final return	
		this.resultSMTPVerifier[ "reason" ]= "Sender Policy not complied";
		this.resultSMTPVerifier[ "result" ]= false;
		return this.resultSMTPVerifier;


	}


	/**
	* @hint returns true if the submitted HELO string is a valid registrered Domain Name (DNS);
	*/
	private boolean function hasSendersValidHelo( 
		required string ipAddress, 
		required string heloSMTPString ){
			
			local.ipAddress = arguments.ipAddress;
			local.heloSMTPString = arguments.heloSMTPString;
				
			local.AforHELODomainDNSEntryArray = listToArray( getDNSRecordByType( heloSMTPString, "A" ), "," );
						
			appendDebugLogLine( "<hr>Found: '#arrayToList(local.AforHELODomainDNSEntryArray)#'" );
						

			cfloop( item="heloAitem" index="t" array="#local.AforHELODomainDNSEntryArray#" ) {

				local.heloAitem = listLast(  heloAitem, " ");
				appendDebugLogLine( "<hr>Verifying if senders IP #t#: '#local.ipAddress#' equals MX IP '#local.heloAitem#'" );
				
		
				if ( local.heloAitem == local.ipAddress ) {

					//SendersIP is MX-Server
					appendDebugLogLine( "senders IP '#local.ipAddress#' is A of MX IP '#local.heloAitem#'" );
					return true;

				} else {

					//SendersIP is NOT MX-Server
					appendDebugLogLine( "senders IP '#local.ipAddress#' is NOT A of MX IP '#local.heloAitem#'" );
				
				}

			}

			return false;

	}

		
	/**
	* @hint returns true if an IPAddress is manually whitelisted;
	*/
	private boolean function isIPAddressWhitelisted( 
		required string ipAddress, 
		required string domainName  ){
			
			local.ipAddress = arguments.ipAddress;
			local.domainName = arguments.domainName;

			// get manual IP Whitelist
			appendDebugLogLine( "Retrieving all hardcoded whitelisted (for '#local.domainName#' and static IP's ");
			local.TmpWhitelistArray = arrayMerge(
						getWhitelistedIPsForDomainArray( local.domainName ),
						getWhitelistedIPsStatic()
					);
										;
			appendDebugLogLine( "IPs: #arrayToList( local.TmpWhitelistArray )#");
			
			// IP Whitelist verification
			if ( arrayContains( local.TmpWhitelistArray, local.ipAddress ) ) {
				return true;
			} else {
				return false;
			};

	}
		
	/**
	* @hint returns true if IP's 'PTR' comes from similar network domain as of email domain
	* Example: t-online.de and mout.t-online.de return true
	*/
	private boolean function isSendersIPAllowedByPTR( 
		required string ipAddress,
		required string domainName ){

			local.ipAddress = arguments.ipAddress;
			local.domainName = arguments.domainName;

			local.inAddrArpaDomain = listToArray( local.ipAddress, ".").reverse().toList(".") & ".in-addr.arpa";
			appendDebugLogLine( "Calling function: getDNSRecordByType( '#encodeforHTML( local.inAddrArpaDomain )#', 'PTR')" );
			local.PTRDomainDNSEntry = getDNSRecordByType( local.inAddrArpaDomain, "PTR" );

			local.PTRDomainDNSEntry = listLast( left( local.PTRDomainDNSEntry, len( local.PTRDomainDNSEntry )-1), " ");
			
			appendDebugLogLine( "DNS QUERY: PTR for IP '#local.ipAddress#' is '#local.PTRDomainDNSEntry#'" );
			
			if ( right(local.PTRDomainDNSEntry, len( "." & local.domainName )) == "." & local.domainName ){
				appendDebugLogLine( "senders IP '#local.ipAddress#' PTR is part of '#local.domainName#'" );
				return true;
			} else {
				appendDebugLogLine( "senders IP '#local.ipAddress#' PTR DOESN't seem to come from '#local.domainName#'" );
				return false;	
			};
	}
		
	/**
	* @hint returns true if IP for a domain name is also listed as 'A' server in DNS;
	*/
	private boolean function isSendersIPAllowedByA( 
		required string ipAddress,
		required string domainName ){

			local.ipAddress = arguments.ipAddress;
			local.domainName = arguments.domainName;

			appendDebugLogLine( "Calling function: getIpByDomain( '#encodeforHTML( local.domainName)#' )" );
			local.ipAddressOfDomainName = getIpByDomain( local.domainName );
			local.ADomainDNSEntry = getDNSRecordByType( local.domainName, "A" );
			appendDebugLogLine( "DNS QUERY: IP Address for '#encodeforHTML(local.domainName)#' is #local.ipAddressOfDomainName#" );
			
			if ( isDefined( "ADomainDNSEntry" ) ) {
			
				appendDebugLogLine( "A-DNS Entries for #local.domainName# are: ""#encodeforHTML(ADomainDNSEntry)#""" );
				appendDebugLogLine( "Now checking if SendersIP is A @#local.domainName#" );
	
				local.ADomainDNSEntryArray = listToArray( ADomainDNSEntry, "," );
				
				cfloop( item="aRecorditem" index="i" array="#ADomainDNSEntryArray#" ) {
					appendDebugLogLine( "<hr>Next A Entry #i#: " & aRecorditem );
					local.aItemListArray = listToArray( aRecorditem, " " );
					local.aItem= listLast(  aRecorditem, " ");

					//remove any available right dot
					if( right( local.aItem, 1 ) == "." ){
						
						appendDebugLogLine( "Cleaning dots from entry" );
						local.aItem= left( local.aItem, -1);
					}
						
					appendDebugLogLine( "Retrieving IP for '#aItem#'" );
					local.aItemIP = getIpByDomain( trim(aItem) );
					appendDebugLogLine( "<hr>Verifying if senders IP '#local.ipAddress#' equals A IP '#local.aItemIP#'" );

					if ( local.aItemIP == local.ipAddress ) {

						//SendersIP is MX-Server
						appendDebugLogLine( "senders IP '#local.ipAddress#' is A IP '#local.aItemIP#'" );
						return true;

					} else {

						//SendersIP is NOT MX-Server
						appendDebugLogLine( "senders IP '#local.ipAddress#' is NOT A IP '#local.aItemIP#'" );
						

					}
						
	
					
				}
	
				return false;
	
			} else {
	
				//SendersIP is NOT A-Server
				appendDebugLogLine( "Domain '#arguments.domainName#' has no IP defined as a A and is NOT a 'A' server" );
				return false;
	
			}

	}

	/**
	* @hint returns true if IP for a domain name is also listed as 'MX' server in DNS;
	*/
	private boolean function isSendersIPAllowedByMX( 
		required string ipAddress,
		required string domainName ){

			local.ipAddress = arguments.ipAddress;
			local.domainName = arguments.domainName;

			appendDebugLogLine( "Calling function: getDNSRecordByType( '#encodeforHTML(local.domainName)#', 'MX')" );
			local.MXDomainDNSEntry = getDNSRecordByType( local.domainName, "MX" );
			

			if ( isDefined( "MXDomainDNSEntry" ) ) {
				
				appendDebugLogLine( "MX-DNS Entrie for #local.domainName# are: ""#encodeforHTML(local.MXDomainDNSEntry)#""" );
				appendDebugLogLine( "Now checking if SendersIP is MX @#local.domainName#" );

				local.MXDomainDNSEntryArray = listToArray( MXDomainDNSEntry, "," );
				appendDebugLogLine( "<hr>Found: '#arrayToList(local.MXDomainDNSEntryArray)#'" );
						
				
				cfloop( item="mxRecorditem" index="i" array="#local.MXDomainDNSEntryArray#" ) {
					local.mxitem= listLast(  mxRecorditem, " ");
					appendDebugLogLine( "<hr>Next MX Entry #i#: " & local.mxitem );
					
					if( right(  local.mxitem, 1 ) == "." ){
						//remove any available right dot
						appendDebugLogLine( "Cleaning dots from entry" );
						local.mxitem = left( mxitem, -1);
					}
					
						
						appendDebugLogLine( "<hr>Retrieving A-Entries of '#mxitem#'" );
							
						local.AforMXDomainDNSEntryArray = listToArray( getDNSRecordByType( mxitem, "A" ), "," );
						appendDebugLogLine( "<hr>Found: '#arrayToList(local.AforMXDomainDNSEntryArray)#'" );
						

						cfloop( item="mxARecorditem" index="t" array="#local.AforMXDomainDNSEntryArray#" ) {

							local.mxAitem = listLast(  mxARecorditem, " ");
							appendDebugLogLine( "<hr>Verifying if senders IP #t#: '#local.ipAddress#' equals MX IP '#local.mxAitem#'" );
							
					
							if ( local.mxAitem == local.ipAddress ) {

								//SendersIP is MX-Server
								appendDebugLogLine( "senders IP '#local.ipAddress#' is A of MX IP '#local.mxAitem#'" );
								return true;

							} else {

								//SendersIP is NOT MX-Server
								appendDebugLogLine( "senders IP '#local.ipAddress#' is NOT A of MX IP '#local.mxAitem#'" );
								

							}

						}
						

					
				}

				return false;

			} else {

				//SendersIP is NOT MX-Server
				appendDebugLogLine( "Domain '#local.domainName#' has no IP defined as a MX and is NOT a 'MX' server" );
				return false;

			}
	}

	/**
	* @hint returns an array of Whitelisted IPs for a domain name;
	*/
	private array function getWhitelistedIPsForDomainArray( required string domainName ) {

		local.domainName = arguments.domainName;


		if ( local.domainName is "t-online.de" ) {
		
			appendDebugLogLine( "Returning array of whitlisted IPs for #local.domainName#" );
			return ["194.25.134.16","194.25.134.17","194.25.134.18","194.25.134.19","194.25.134.20","194.25.134.21","194.25.134.22","194.25.134.80","194.25.134.81","194.25.134.82","194.25.134.83","194.25.134.84","194.25.134.85","194.25.134.86"]
		
		} else if ( local.domainName is "somedomain.cctld" ) {
		
			appendDebugLogLine(  "Returning array of whitlisted IPs for #local.domainName#" );
			return ["194.25.134.16","194.25.134.17"]
		
		} else {
		
			return [];
		
		}
	}


	/**
	* @hint returns an array of static whitelisted IPs;
	*/
	private array function getWhitelistedIPsStatic() {

		return [
			"194.25.134.16",
			"194.25.134.17",
			]
	}

	/**
	 * @hint returns true if the given IPv4 address range (ipRange) contains the given IP address (ipAddress).
	 * 
	 * This function uses part of 'IPAddress' project which is released under 'Apache-2.0 License'.
	 * See file \jars\ipaddress-5.3.3.jar or go to https://github.com/seancfoley/IPAddress/blob/master/LICENSE 
	 * for full license details.
	 * 
	 * */
	private boolean function isIpInRanges(
			required string ipRange,
			required string ipAddress ){
		
			local.ipAddresses = CreateObject( "java", "java.net.InetAddress" );
			local.objIPAddress = createObject( "java", "inet.ipaddr.IPAddressString" ) ;
			local.IPAddressNetwork = objIPAddress.init( arguments.ipRange );
			local.IPAddressIpAddress = objIPAddress.init( arguments.ipAddress );
			return local.IPAddressNetwork.contains( local.IPAddressIpAddress ) ; 
		
	}


	/**
	 * @hint Get the IP address for a domain name from DNS
	 **/
		private string function getIpByDomain(
			required string domainName ) {

				local.domainName = arguments.domainName;

				try {
					local.iaddr = CreateObject( "java", "java.net.InetAddress" );
					local.tmpipaddress = iaddr.getByName( local.domainName ).getHostAddress();
					return local.tmpipaddress;
				} catch ( any e ) {
					//return invalid IPs as IP4
					return "0.0.0.0";
				}
		}


	/**
	 * @hint Get a DNS entry as a string by entry type. Code slighly adapted from Pete Freitags awesome 
	 * blog entry at https://www.petefreitag.com/item/487.cfm
	 */
	private string function getDNSRecordByType(
		required string domainName,
		required string entrytype ) {

			local.domainName = arguments.domainName;
			local.entrytype = arguments.entrytype;

			try {

					local.javaObjHashtable = CreateObject( "java", "java.util.Hashtable" );
					local.javaObjHashtable.put( "java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory" );
					local.javaObjHashtable.put( "java.naming.provider.url", "dns://8.8.8.8" );
					local.javaObjHashtable.put( "com.sun.jndi.dns.timeout.initial", "2000" );
					local.javaObjHashtable.put( "com.sun.jndi.dns.timeout.retries", "3" );

					local.tmptype = ArrayNew( 1 );
					local.tmptype[ 1 ] = local.entrytype;
					local.domainname = local.domainName;
				
					local.dirContext = CreateObject( "java", "javax.naming.directory.InitialDirContext" );
					local.dirContext.init( local.javaObjHashtable );

					local.tmpattributes = local.dirContext.getAttributes( local.domainName, local.tmptype );
					local.attribEnum = local.tmpattributes.getAll();

					while ( local.attribEnum.hasMore() ) {

						local.attribute = attribEnum.next();
						return local.attribute.toString();
					
					}
			
			} catch ( any e ) {
				// return empty string
				return "" ;
			}
	}



	/**
	 * @hint returns true if the submitted IP Address (IPv4) is allowed by SPF to send for a DomainName 
	 */
	private boolean function isSendersIpAllowedBySPF(
		required string ipAddress,
		required string domainName,
		required numeric spfHops = 0 ) {

			local.spfHops = arguments.spfHops;
			local.domainsAlreadyChecked= []; 
			local.ipAddress= arguments.ipAddress; 
			local.domainName= arguments.domainName; 

			try {

				appendDebugLogLine( "*** SPF-HOP INIT VALUE #local.spfHops#***: Check if SenderIP #local.ipAddress# is allowed to send as specified in SPF-Entry made by #local.domainName#");
				
				// Not allow more then 9 Hops
				if ( local.spfHops >= 10 ) {

					return false;

				};

				if ( local.spfHops == 0 ) {
				
					// first round: initialize and populate array of already verified domains.
					arrayAppend ( local.domainsAlreadyChecked, replacenocase( local.domainName, ".", "_", "ALL") );
					appendDebugLogLine( "++++++ SPF check initialized spfHops:#local.spfHops# ++++++" );
					appendDebugLogLine( "Domain '#local.domainName#' added to domainsAlreadyChecked array."  );
				
				} else {

					if ( arrayContains( local.domainsAlreadyChecked, replacenocase( local.domainName, ".", "_", "ALL" ) ) ) {
						appendDebugLogLine( "<b>'#local.domainsAlreadyChecked#' DOMAIN ALREADY CHECKED! Quit</b>" );
						return false;
					};

				};

				local.spfHops++;

				appendDebugLogLine( "SPF-HOP #local.spfHops#: Calling function getDNSRecordByType( '#local.domainName#', 'TXT') to retrieve a comma separed list of quoted strings for all DNS 'TXT'" );
				local.dnsRecord = getDNSRecordByType( local.domainName, "TXT" );
				appendDebugLogLine( "<b>SPF-HOP #local.spfHops# DNS TXTs RECORDs RETRIEVED (comma separed list of quoted strings):</b><div style='border:1px solid navy;min-height:20px;padding:5px;max-width:500px;'>#encodeForHTML(local.dnsRecord)#</div>" );

				if ( findNoCase( "v=spf1", local.dnsRecord ) ) {

					local.pos1 = findNoCase( "v=spf1", local.dnsRecord );
					local.pos2 = findNoCase( chr( 34 ), local.dnsRecord, local.pos1 + 1 );
					local.spfrecord = mid( local.dnsRecord, local.pos1, local.pos2 - local.pos1 );

					appendDebugLogLine( "spfrecord: #local.spfrecord#" );
					local.SpfListArray = listToArray( local.spfrecord, " " );
					
					for ( local.spfitem in local.SpfListArray ) {

						appendDebugLogLine( "ITEM: #local.spfitem#" );
						local.DNSRecordTypesInfSPF = [ "A", "MX" ];

						for ( local.DNSRecordType in local.DNSRecordTypesInfSPF ) {
							
							// DNS A records for domain
							if ( local.spfitem == local.DNSRecordType ) {
								
								local.tmpipaddress = getIpByDomain( local.domainName );
								appendDebugLogLine( "#local.DNSRecordType#:#local.tmpipaddress#" );

								if ( tmpipaddress == local.ipAddress ) {
									appendDebugLogLine( "SenderIPAddress is #local.DNSRecordType#:#local.tmpipaddress#" );
									return true;

								}

							}


							// DNS A/ records for domain (all IPs in defined Range)
							if ( left( local.spfitem, len( "#local.DNSRecordType#/" ) ) == "#local.DNSRecordType#/" ) {
								
								local.tmpipaddress = getIpByDomain( local.domainName );
								appendDebugLogLine("isIpInRanges( #local.tmpipaddress##replacenocase( local.spfitem,'#local.DNSRecordType#/','/','ALL' )# , #local.ipAddress#);"); 
								return local.isIpInRanges( local.tmpipaddress & replacenocase( local.spfitem,"#local.DNSRecordType#/","/","ALL" ) , local.ipAddress);	
							
							}


							// DNS A: records of named domain with ranges
							if ( left( local.spfitem, len( "#local.DNSRecordType#:" ) ) == "#local.DNSRecordType#:" ) {

								appendDebugLogLine( "#local.DNSRecordType#: FOUND!!!" );

								if ( findNoCase( "/", local.spfitem ) ) {

									local.ipOfDomain = getIpByDomain( replacenocase( listfirst( local.spfitem, "/" ), "#local.DNSRecordType#:", "", "ALL" ) );
									appendDebugLogLine( "Allowed SendersIP is: " &  local.IpOfDomain & "/" & listlast( local.spfitem,"/") & "" );
									
									return isIpInRanges( local.ipOfDomain & "/" & listlast( local.spfitem, "/" ), arguments.ipAddress );

								} else {

									local.ipOfDomain = getIpByDomain( replacenocase( local.spfitem, "#local.DNSRecordType#:", "", "ALL" ) );
									appendDebugLogLine( "Allowed SendersIP is: " & local.ipOfDomain & "" );

									if ( local.ipOfDomain == local.ipAddress ) {
										return true;
									};
								};
							};
						};


						if ( left( local.spfitem, len( "ip4:" ) ) == "ip4:" ) {

							local.tmpisIpInRanges = isIpInRanges( listLast( local.spfitem, ":" ), local.ipAddress );
					
								if ( local.tmpisIpInRanges is true ) {
									appendDebugLogLine( "Ip #local.ipAddress# is in range '#listLast( local.spfitem, ":" )#'" );
									return true;
								} else {
									appendDebugLogLine( "Ip #local.ipAddress# is NOT in range '#listLast( local.spfitem, ":" )#'" );
								}

							
						}


						local.SPFRecordTypesInSPF = [ "include:", "redirect=" ];

						for ( local.SPFRecordType in local.SPFRecordTypesInSPF ) {

							if ( left( local.spfitem, len( local.SPFRecordType ) ) == local.SPFRecordType ) {

								appendDebugLogLine( "Checking #local.spfitem#" );
								local.includeDomainName = replacenocase( local.spfitem, local.SPFRecordType, "", "ALL" );
								appendDebugLogLine( "#local.spfitem#: Rekursive call isSendersIpAllowedBySPF('#local.ipAddress#','#local.includeDomainName#',#local.spfHops#);" );
								local.tmpisSendersIpAllowedBySPF = isSendersIpAllowedBySPF( local.ipAddress, local.includeDomainName, local.spfHops );

								if ( local.tmpisSendersIpAllowedBySPF ) {

									return true;

								};

							};

						};
					};
				};



			} catch ( any e ) {
				writedump( e );
			};
		
			appendDebugLogLine( "No valid verfications passed! Set to false");
			return false;

	}


}
</cfscript>