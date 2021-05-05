<cfscript>
    cftimer(label="Nap time" type="outline"){
        SMTPverifier = new StrictSMTPSenderValidator( debugLogLevel = 1 );
        smtpIsAllowed=SMTPverifier.isSendersIPAllowedForemailAddress( "104.47.58.33" , "@gmx.de");
        echo( SMTPverifier.debugLog );
        
        if( smtpIsAllowed.result ){
            echo( "CHECK PASSED");
        } else {
            echo( "CHECK FAILED");
        }
        writeDump( smtpIsAllowed );
    }

    cftimer(label="Nap time" type="outline"){
        SMTPverifier = new StrictSMTPSenderValidator( debugLogLevel = 1 );
        smtpIsAllowed=SMTPverifier.isSendersIPAllowedForemailAddress( "64.233.160.1" , "@web.de");
        echo( SMTPverifier.debugLog );
        
        if( smtpIsAllowed.result ){
            echo( "CHECK PASSED");
        } else {
            echo( "CHECK FAILED");
        }
        writeDump( smtpIsAllowed );
    }
</cfscript>



