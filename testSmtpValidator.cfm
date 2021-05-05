<cfscript>
    cftimer(label="Nap time" type="outline"){
        SMTPverifier = new StrictSPFSenderValidator( debugLogLevel = 1 );
        smtpIsAllowed= SMTPverifier.isSendersIPAllowedForEmailAddress( "104.47.58.33" , "@gmx.de");
        
        echo( SMTPverifier.debugLog );
        
        if( smtpIsAllowed.result ){
            echo( "CHECK PASSED");
        } else {
            echo( "CHECK FAILED");
        }
        writeDump( smtpIsAllowed );
    }

    cftimer(label="Nap time" type="outline"){
        SMTPverifier = new StrictSPFSenderValidator( debugLogLevel = 0 );
        echo( "SMTPverifier.isSendersIPAllowedForEmailAddress( ""212.227.15.3"" , ""@web.de""):<br>" );
        smtpIsAllowed=SMTPverifier.isSendersIPAllowedForEmailAddress( "212.227.15.3" , "@web.de");
        if( smtpIsAllowed.result ){
            echo( "CHECK PASSED");
        } else {
            echo( "CHECK FAILED");
        }
        writeDump( smtpIsAllowed );
    }


    cftimer(label="Nap time" type="outline"){
        SMTPverifier = new StrictSPFSenderValidator( debugLogLevel = 1 );
        echo( "SMTPverifier.isSendersIPAllowedForEmailAddress( ""157.56.110.65"" , ""@outlook.com""):<br>" );
        smtpIsAllowed=SMTPverifier.isSendersIPAllowedForEmailAddress( "157.56.110.65" , "@outlook.com");
        echo( SMTPverifier.debugLog );
        if( smtpIsAllowed.result ){
            echo( "CHECK PASSED");
        } else {
            echo( "CHECK FAILED");
        }
        writeDump( [smtpIsAllowed ] );
    }
</cfscript>



