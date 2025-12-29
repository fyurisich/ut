// --------------------------------------------- //
// Recover IP Real Mejorada v2.0
// Para reverse proxy, Cloudflare Tunnel,...
// Filtra IPs locales y privadas (IPv4 + IPv6)
// Incluye validaciones adicionales de rangos RFC
// --------------------------------------------- //

FUNCTION UGetIpClient( hServer )   // CAF

    local aIP := {;
        'HTTP_X_FORWARDED_FOR',;
        'HTTP_CF_CONNECTING_IP',;   // Prioridad máxima para Cloudflare		
        'HTTP_X_REAL_IP',;
        'HTTP_CLIENT_IP',;
        'REMOTE_ADDR'; 
    }
    
    local nLen := Len( aIP )
    local nI, cValue, aForward, cKey, cIp 
	
    local o := UGetServer()

    //o:LogError( '>> UGetIp()' )

	
    for nI := 1 TO nLen 
	
        cKey := aIP[ nI ]

        //o:LogError( '--> Key: ' + cKey )
        
        if HB_HHasKey( hServer, cKey ) 
		
            //o:LogError( '--> Found !' )
		
            cValue := AllTrim( hServer[ cKey ] )  // Limpia espacios extra
			
            //o:LogError( '--> Value: ' + cValue )
	           
            if !Empty( cValue )  // Verifica que no esté vacío
			
                if cKey == 'HTTP_X_FORWARDED_FOR'
                    // Maneja cadena de IPs (e.g., "client_ip, proxy1, proxy2")
                    // Toma solo la primera IP pública (el cliente real)
                    aForward := hb_ATokens( cValue, "," )
                    
                    if ValType( aForward ) == 'A' .AND. Len( aForward ) > 0 
                        
                        // Verifica cada posible IP en la cadena, pero prioriza la primera pública
                        for each cIp in aForward						
						
                            cIp := AllTrim( cIp )
                            //o:LogError( '--> HTTP_X_FORWARDED_FOR: ' + cIp )
                           
                            if UValidIP( cIp ) .AND. UIsPublicIP( cIp )
							
                                //o:LogError( '--> HTTP_X_FORWARDED_FOR: Validated ! ' )
                                return cIp
                            endif
                        next
                    endif
                    
                    // *** FIX CRÍTICO: Si no encontró IP pública en X-Forwarded-For, 
                    // continuar al siguiente header sin intentar validar cIp 
                    // (que contendría la última IP del array, posiblemente privada)
                    loop
                    
                else 
                    cIp := cValue 
                    
                    // Valida otros headers directamente
                    if UValidIP( cIp ) .AND. UIsPublicIP( cIp )
                        //o:LogError( '--> ValidIP: ' + cIp  )
                        return cIp 
                    endif
                endif

            endif
        endif     
    next     
	
    //o:LogError( '--> No public IP found, returning 127.0.0.1'  )
	
return '127.0.0.1'

// --------------------------------------------- //
// Valida formato IPv4 o IPv6
// --------------------------------------------- //

FUNCTION UValidIP( cIP ) 

    local lValid := .F.
	
    
    if Empty( cIP )
        return .F.
    endif
    
    // Detecta si es IPv6 (contiene ":")
    if ":" $ cIP
        lValid := UValidIPv6( cIP )
    else
        lValid := UValidIPv4( cIP )
    endif

    return lValid

// --------------------------------------------- //
// Valida formato IPv4 básico
// --------------------------------------------- //

STATIC FUNCTION UValidIPv4( cIP ) 

    local lValid := .F.
    local cPatron := "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"


    if !Empty( cIP ) .AND. HB_RegExMatch( cPatron, cIP )
        lValid := .T.
    endif

    return lValid

// --------------------------------------------- //
// Valida formato IPv6 (incluyendo formato comprimido con ::)
// Ahora incluye soporte para IPv4-mapped IPv6 (::ffff:192.0.2.1)
// --------------------------------------------- //

STATIC FUNCTION UValidIPv6( cIP )

    local lValid := .F.
    local cPatronFull, cPatronComprimido, cPatronIPv4Mapped
    
    if Empty( cIP )
        return .F.
    endif
    


    // Patrón para IPv6 completa (8 grupos de 1-4 dígitos hex separados por :)
    cPatronFull := "^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
    
    // Patrón para IPv6 comprimida (permite :: para secuencias de ceros)
    // Acepta formatos como: ::1, fe80::1, 2800:810:46d:10::1, etc.
    cPatronComprimido := "^(([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$"
    
    // Patrón para IPv4-mapped IPv6 (::ffff:192.0.2.1)
    cPatronIPv4Mapped := "^::ffff:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    
    // Valida con los tres patrones
    if HB_RegExMatch( cPatronFull, cIP ) .OR. ;
       HB_RegExMatch( cPatronComprimido, cIP ) .OR. ;
       HB_RegExMatch( cPatronIPv4Mapped, Lower(cIP) )
        lValid := .T.
    endif
    
    return lValid

// --------------------------------------------- //
// Verifica si IP es pública (no local/privada)
// Soporta IPv4 e IPv6
// --------------------------------------------- //

STATIC FUNCTION UIsPublicIP( cIP )

    local lPublic := .F.
    
    if !UValidIP( cIP )
        return .F.
    endif
 
    // Detecta si es IPv6 (contiene ":")
    if ":" $ cIP
        lPublic := UIsPublicIPv6( cIP )
    else
        lPublic := UIsPublicIPv4( cIP )
    endif
	
    return lPublic

// --------------------------------------------- //
// Verifica si IPv4 es pública (no local/privada)
// Excluye rangos RFC 1918, loopback, link-local,
// Carrier-Grade NAT, benchmark, multicast, etc.
// --------------------------------------------- //

STATIC FUNCTION UIsPublicIPv4( cIP )

    local lPublic := .F.
    local aParts, nOct1, nOct2, nOct3
    
    if !UValidIPv4( cIP )
        return .F.
    endif
 
    // Split en octetos
    aParts := hb_ATokens( cIP, "." )
    if Len( aParts ) != 4
        return .F.
    endif
    
    nOct1 := Val( aParts[1] )
    nOct2 := Val( aParts[2] )
    nOct3 := Val( aParts[3] )
    
    // Excluye 0.0.0.0/8 (This network)
    if nOct1 == 0
        return .F.
    endif
    
    // Excluye loopback (127.0.0.0/8)
    if nOct1 == 127
        return .F.
    endif
    
    // Excluye privados RFC 1918: 10.0.0.0/8
    if nOct1 == 10
        return .F.
    endif
    
    // Excluye privados RFC 1918: 172.16.0.0/12 (172.16-31)
    if nOct1 == 172 .AND. nOct2 >= 16 .AND. nOct2 <= 31
        return .F.
    endif
    
    // Excluye privados RFC 1918: 192.168.0.0/16
    if nOct1 == 192 .AND. nOct2 == 168
        return .F.
    endif
    
    // Excluye link-local (169.254.0.0/16)
    if nOct1 == 169 .AND. nOct2 == 254
        return .F.
    endif
    
    // Excluye Carrier-Grade NAT (100.64.0.0/10) - RFC 6598
    if nOct1 == 100 .AND. nOct2 >= 64 .AND. nOct2 <= 127
        return .F.
    endif
    
    // Excluye benchmark testing (198.18.0.0/15) - RFC 2544
    if nOct1 == 198 .AND. (nOct2 == 18 .OR. nOct2 == 19)
        return .F.
    endif
    
    // Excluye TEST-NET ranges (documentation)
    // 192.0.0.0/24, 198.51.100.0/24, 203.0.113.0/24
    if (nOct1 == 192 .AND. nOct2 == 0 .AND. nOct3 == 0) .OR. ;
       (nOct1 == 198 .AND. nOct2 == 51 .AND. nOct3 == 100) .OR. ;
       (nOct1 == 203 .AND. nOct2 == 0 .AND. nOct3 == 113)
        return .F.
    endif
    
    // Excluye multicast (224.0.0.0/4) y reserved (240.0.0.0/4)
    if nOct1 >= 224
        return .F.
    endif
    
    lPublic := .T.
	
    return lPublic

// --------------------------------------------- //
// Verifica si IPv6 es pública (no local/privada)
// Excluye loopback (::1), link-local (fe80::/10),
// unique local addresses (fc00::/7), y multicast
// --------------------------------------------- //

STATIC FUNCTION UIsPublicIPv6( cIP )

    local lPublic := .T.
    local cIPLower, cIPv4Part
    
    if !UValidIPv6( cIP )
        return .F.
    endif
   
    cIPLower := Lower( AllTrim( cIP ) )
    
    // Excluye loopback (::1)
    if cIPLower == "::1"
        return .F.
    endif
    
    // Excluye link-local (fe80::/10)
    // Todas las direcciones que empiezan con fe80:
    if Left( cIPLower, 4 ) == "fe80"
        return .F.
    endif
    
    // Excluye unique local addresses (fc00::/7)
    // Incluye fc00:: y fd00::
    if Left( cIPLower, 2 ) == "fc" .OR. Left( cIPLower, 2 ) == "fd"
        return .F.
    endif
    
    // Excluye multicast (ff00::/8)
    if Left( cIPLower, 2 ) == "ff"
        return .F.
    endif
    
    // Excluye :: (sin especificar)
    if cIPLower == "::"
        return .F.
    endif
    
    // Excluye IPv4-mapped addresses privadas (::ffff:192.168.x.x, etc.)
    if "::ffff:" $ cIPLower
	
        // Extrae la parte IPv4 y valídala
        cIPv4Part := SubStr( cIPLower, At("::ffff:", cIPLower) + 7 )
		
        if !UIsPublicIPv4( cIPv4Part )
            return .F.
        endif
		
    endif
    
return lPublic
