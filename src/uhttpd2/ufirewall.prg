// ===============================================================
// Firewall IP Filter Parser - Soporte Dual IPv4/IPv6 en Harbour
// ===============================================================
//
// Autor      : AI Assistant (basado en conversaciones previas)
// Supervisor : Carles Aubia :-)
// Fecha      : 07-Nov-2025
// Descripción: Parser de filtros de firewall con soporte para IPv4 e IPv6 en formato CIDR.
//              Maneja rangos permitidos y denegados con merge automático de intervalos.
//              Optimizado para servidores web como HIX con Cloudflare.
//              Uso: UParseFirewallFilter(cFilterString, @aFilter, .T.) para sorted array.
//              Validación: UIsIPAllowed(cClientIP, aFilter)
//              
// Requisitos : Harbour/xHarbour con funciones hb_ standard (regex, bit operations)
// Notas      : IPv4 como array {nIP32bit}, IPv6 como {word0, word1, word2, word3} (4x32bit)
//              Palabras: big-endian, cada word = 2 hextetos IPv6 (16-bit cada uno)
//
// ==============================================================

// Convierte IP string a array de words (IPv4: {nIP}, IPv6: {w0,w1,w2,w3})

FUNCTION UIPAddr2Num( cIP )

   LOCAL aMatch, nI, nIp, aWords := {}, nHext
   LOCAL cRegexIPv4 := "^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$"
   LOCAL n1, n2, n3, n4 , cFullHex, nWordIdx

   // IPv4 parsing
   aMatch := hb_regex( cRegexIPv4, cIP )
   
   IF Len( aMatch ) == 5
   
      n1 := Val( aMatch[2] )
	  n2 := Val( aMatch[3] )
	  n3 := Val( aMatch[4] )
	  n4 := Val( aMatch[5] )
	  
      IF n1 <= 255 .AND. n2 <= 255 .AND. n3 <= 255 .AND. n4 <= 255
         nIP := ( ( ( n1 * 256 ) + n2 ) * 256 + n3 ) * 256 + n4
         RETURN { nIP }  // Array de 1 word para IPv4
      ENDIF
	  
   ENDIF

   // IPv6 parsing
   IF "::" $ cIP .OR. ":" $ cIP  // Quick check for IPv6
      cFullHex := ExpandIPv6( cIP )
      IF Len( cFullHex ) == 32  // Valid 128-bit hex
         aWords := Array(4)
         FOR nI := 1 TO 8  // 8 hextetos
            nHext := Val( "0x" + SubStr( cFullHex, (nI-1)*4 + 1, 4 ) )  // 16-bit hex to decimal
            nWordIdx := Int( (nI + 1) / 2 )
            IF nI % 2 == 1
               aWords[nWordIdx] := nHext * 65536  // << 16
            ELSE
               aWords[nWordIdx] += nHext
            ENDIF
         NEXT
         RETURN aWords  // 4 words de 32-bit
      ENDIF
   ENDIF
   
RETURN {}  // Invalid IP

// Parser principal de filtros de firewall
FUNCTION UParseFirewallFilter( cFilter, aFilterOut, lSorted )

   LOCAL cExpr, lDeny, aDeny := {}, aTemp := {}, aAllow := {}
   LOCAL nI, cI, nPrefix, aAddr, aStart, aEnd, lIPv6, aMaskIP, aInterval

   hb_default( @lSorted, .T. )
   aFilterOut := NIL

   FOR EACH cExpr IN hb_ATokens( cFilter, " " )
      IF Empty( cExpr ) ; LOOP ; ENDIF

      lDeny := ( Left( cExpr, 1 ) == "!" )
      IF lDeny ; cExpr := SubStr( cExpr, 2 ) ; ENDIF

      // Explicit range "start-end"
      IF ( nI := At( "-", cExpr ) ) > 0
         aStart := UIPAddr2Num( Left( cExpr, nI - 1 ) )
         aEnd := UIPAddr2Num( SubStr( cExpr, nI + 1 ) )
         IF Empty( aStart ) .OR. Empty( aEnd ) .OR. ! CompareIPs( aStart, "<=", aEnd )
            RETURN .F.
         ENDIF
      ELSEIF ( nI := At( "/", cExpr ) ) > 0
         cI := SubStr( cExpr, nI + 1 )
         cExpr := Left( cExpr, nI - 1 )
         aAddr := UIPAddr2Num( cExpr )
         IF Empty( aAddr ) ; RETURN .F. ; ENDIF

         nPrefix := Val( cI )
         lIPv6 := ( Len( aAddr ) == 4 )
         IF lIPv6 .AND. ( nPrefix < 0 .OR. nPrefix > 128 ) ; RETURN .F. ; ENDIF
         IF !lIPv6 .AND. ( nPrefix < 0 .OR. nPrefix > 32 ) ; RETURN .F. ; ENDIF

         // Dotted mask for IPv4 only
         IF !lIPv6 .AND. "." $ cI
            aMaskIP := UIPAddr2Num( cI )
            IF Empty( aMaskIP ) ; RETURN .F. ; ENDIF
            IF ! IsValidNetmask( aMaskIP[1] ) ; RETURN .F. ; ENDIF  // Validar máscara contigua
            nPrefix := BitCount( aMaskIP[1] )
         ENDIF

         aStart := ApplyMask( aAddr, nPrefix, lIPv6 )
         aEnd := ApplyInvertedMask( aAddr, nPrefix, lIPv6 )
      ELSE
         aStart := aEnd := UIPAddr2Num( cExpr )
         IF Empty( aStart ) ; RETURN .F. ; ENDIF
      ENDIF

      IF !lDeny
         aInterval := { "type" => IIF( Len(aStart)==1, "v4", "v6" ), "start" => aStart, "end" => aEnd }
         AAdd( aTemp, aInterval )
      ELSE
         AAdd( aDeny, { aStart, aEnd } )
      ENDIF
   NEXT

   // Sort and merge allows
   ASort( aTemp, , , , {|x,y| CompareIPs( x["start"], "<", y["start"] ) } )
   aAllow := MergeIntervalsDual( aTemp )

   // Subtract denies
   aAllow := SubtractIntervalsDual( aAllow, aDeny )

   aFilterOut := IIF( lSorted, aAllow, ToHashDual( aAllow ) )
   
RETURN .T.

// Verifica si una IP está permitida por el filtro
FUNCTION UIsIPAllowed( cClientIP, aFilter )

   LOCAL aIP := UIPAddr2Num( cClientIP )
   LOCAL nPos := 0
   
   IF Empty( aIP ) ; RETURN .F. ; ENDIF

   AEval( aFilter, {|x, n| ;
            if ( Len( aIP ) == Len( x["start"] ) .AND. ;
               CompareIPs( aIP, ">=", x["start"] ) .AND. ;
               CompareIPs( aIP, "<=", x["end"] ),  ; 
               nPos := n, nil) } )
			
RETURN nPos > 0

// Convierte array numérico a string IP (debug)
STATIC FUNCTION Num2IP( aNum )
   LOCAL cIP := "", i, nWord, cHexWord

   IF Len( aNum ) == 1  // IPv4
      nWord := aNum[1]
      cIP := AllTrim( Str( hb_bitShift( nWord, -24 ) ) ) + "." + ;
             AllTrim( Str( hb_bitAnd( hb_bitShift( nWord, -16 ), 0xFF ) ) ) + "." + ;
             AllTrim( Str( hb_bitAnd( hb_bitShift( nWord, -8 ), 0xFF ) ) ) + "." + ;
             AllTrim( Str( hb_bitAnd( nWord, 0xFF ) ) )
   ELSE  // IPv6
      FOR i := 1 TO 4
         nWord := aNum[i]
         // Convertir 32-bit a 8 hex chars
         cHexWord := ""
         cHexWord += hb_NumToHex( hb_bitShift( nWord, -28 ), 1 )
         cHexWord += hb_NumToHex( hb_bitAnd( hb_bitShift( nWord, -24 ), 0xF ), 1 )
         cHexWord += hb_NumToHex( hb_bitAnd( hb_bitShift( nWord, -20 ), 0xF ), 1 )
         cHexWord += hb_NumToHex( hb_bitAnd( hb_bitShift( nWord, -16 ), 0xF ), 1 )
         cHexWord += hb_NumToHex( hb_bitAnd( hb_bitShift( nWord, -12 ), 0xF ), 1 )
         cHexWord += hb_NumToHex( hb_bitAnd( hb_bitShift( nWord, -8 ), 0xF ), 1 )
         cHexWord += hb_NumToHex( hb_bitAnd( hb_bitShift( nWord, -4 ), 0xF ), 1 )
         cHexWord += hb_NumToHex( hb_bitAnd( nWord, 0xF ), 1 )
         
         // Agregar hextetos con :
         cIP += SubStr( cHexWord, 1, 4 ) + ":" + SubStr( cHexWord, 5, 4 ) + ":"
      NEXT
      cIP := Left( cIP, Len( cIP ) - 1 )  // Quitar último :
   ENDIF
   
RETURN cIP

// --- FUNCIONES INTERNAS (STATIC) ---

// Expande IPv6 compressed (::, leading zeros) a 32 hex chars
STATIC FUNCTION ExpandIPv6( cIP )

   LOCAL aParts, aLeft := {}, aRight := {}, cFull := "", nI
   LOCAL nColonPos, nZerosNeeded, cPart

   // Manejar :: (compressed zeros)
   IF "::" $ cIP
      nColonPos := At( "::", cIP )
      
      IF nColonPos > 1
         aLeft := hb_ATokens( Left( cIP, nColonPos - 1 ), ":" )
      ENDIF
      
      IF nColonPos + 1 < Len( cIP )
         aRight := hb_ATokens( SubStr( cIP, nColonPos + 2 ), ":" )
      ENDIF
      
      nZerosNeeded := 8 - Len( aLeft ) - Len( aRight )
      IF nZerosNeeded < 0 ; RETURN "" ; ENDIF
      
      aParts := AClone( aLeft )
      FOR nI := 1 TO nZerosNeeded
         AAdd( aParts, "0" )
      NEXT
      AEval( aRight, {|x| AAdd( aParts, x ) } )
   ELSE
      aParts := hb_ATokens( cIP, ":" )
   ENDIF

   IF Len( aParts ) != 8 ; RETURN "" ; ENDIF

   // Pad y concatenar
   FOR EACH cPart IN aParts
      cPart := Upper( AllTrim( cPart ) )
      IF Len( cPart ) > 4 ; RETURN "" ; ENDIF
      cFull += Right( "0000" + cPart, 4 )
   NEXT
   
RETURN cFull

// Aplica máscara de red (network address)
STATIC FUNCTION ApplyMask( aIP, nPrefix, lIPv6 )

   LOCAL aMasked := AClone( aIP ), nWord, nBitsInWord, nWords := IIF( lIPv6, 4, 1 )
   LOCAL nMask

   FOR nWord := 1 TO nWords
      nBitsInWord := Max( 0, Min( nPrefix, 32 ) )
      
      IF nBitsInWord == 0
         nMask := 0
      ELSEIF nBitsInWord == 32
         nMask := 0xFFFFFFFF
      ELSE
         nMask := hb_bitShift( 0xFFFFFFFF, -(32 - nBitsInWord) )
      ENDIF
      
      aMasked[nWord] := hb_bitAnd( aIP[nWord], nMask )
      nPrefix -= 32
      IF nPrefix <= 0 ; EXIT ; ENDIF
   NEXT
   
RETURN aMasked

// Aplica máscara invertida (broadcast address)
STATIC FUNCTION ApplyInvertedMask( aIP, nPrefix, lIPv6 )

   LOCAL aEnd := AClone( aIP )
   LOCAL nWords := IIF( lIPv6, 4, 1 )
   LOCAL nBitsOff := IIF( lIPv6, 128 - nPrefix, 32 - nPrefix )
   LOCAL nFreeBits, nWord, nMask

   FOR nWord := nWords TO 1 STEP -1
      nFreeBits := Max( 0, Min( nBitsOff, 32 ) )
      
      IF nFreeBits == 0
         nMask := 0
      ELSEIF nFreeBits == 32
         nMask := 0xFFFFFFFF
      ELSE
         nMask := hb_bitShift( 1, nFreeBits ) - 1
      ENDIF
      
      aEnd[nWord] := hb_bitOr( aEnd[nWord], nMask )
      nBitsOff -= 32
      IF nBitsOff <= 0 ; EXIT ; ENDIF
   NEXT
   
RETURN aEnd

// Compara dos IPs multi-word
STATIC FUNCTION CompareIPs( aIP1, cOp, aIP2 )
   LOCAL nWords1 := Len( aIP1 ), nWords2 := Len( aIP2 ), i
   LOCAL nCmp := 0  // -1 = less, 0 = equal, 1 = greater

   IF nWords1 != nWords2 ; RETURN .F. ; ENDIF

   // Comparación lexicográfica
   FOR i := 1 TO nWords1
      IF aIP1[i] < aIP2[i]
         nCmp := -1
         EXIT
      ELSEIF aIP1[i] > aIP2[i]
         nCmp := 1
         EXIT
      ENDIF
   NEXT

   // Evaluar operador
   DO CASE
      CASE cOp == "==" .OR. cOp == "="
         RETURN nCmp == 0
      CASE cOp == "<"
         RETURN nCmp < 0
      CASE cOp == "<="
         RETURN nCmp <= 0
      CASE cOp == ">"
         RETURN nCmp > 0
      CASE cOp == ">="
         RETURN nCmp >= 0
      CASE cOp == "!=" .OR. cOp == "<>"
         RETURN nCmp != 0
      OTHERWISE
         RETURN .F.
   ENDCASE

RETURN .F.

// Merge de intervalos adyacentes/solapados
STATIC FUNCTION MergeIntervalsDual( aIntervals )

   LOCAL aMerged := {}, nI, aCurrStart, aCurrEnd, aInt, cType

   IF Empty( aIntervals ) ; RETURN aMerged ; ENDIF

   aCurrStart := aIntervals[1]["start"]
   aCurrEnd := aIntervals[1]["end"]
   cType := aIntervals[1]["type"]

   FOR nI := 2 TO Len( aIntervals )
      aInt := aIntervals[nI]
      //IF AdjacentOrOverlap( aCurrStart, aCurrEnd, aInt["start"] )
      IF AdjacentOrOverlap( aCurrEnd, aInt["start"] )
         aCurrEnd := MaxEnd( aCurrEnd, aInt["end"] )
      ELSE
         AAdd( aMerged, { "type" => cType, "start" => aCurrStart, "end" => aCurrEnd } )
         aCurrStart := aInt["start"]
         aCurrEnd := aInt["end"]
         cType := aInt["type"]
      ENDIF
   NEXT
   
   AAdd( aMerged, { "type" => cType, "start" => aCurrStart, "end" => aCurrEnd } )

RETURN aMerged

// Substrae rangos denegados de los permitidos
STATIC FUNCTION SubtractIntervalsDual( aAllows, aDenies )

   LOCAL aResult := {}, aTempSubs := {}, xAllow, xDeny
   LOCAL aSubEnd, aRemainingStart, aRemainingEnd

   IF Empty( aAllows ) .OR. Empty( aDenies ) ; RETURN aAllows ; ENDIF

   FOR EACH xAllow IN aAllows
      aTempSubs := {}
      aRemainingStart := AClone( xAllow["start"] )
      aRemainingEnd := AClone( xAllow["end"] )

      FOR EACH xDeny IN aDenies
         IF Empty( aRemainingStart ) ; EXIT ; ENDIF
         
         IF ! OverlapsWith( aRemainingStart, aRemainingEnd, xDeny[1], xDeny[2] )
            LOOP
         ENDIF

         // Parte ANTES del deny
         IF CompareIPs( aRemainingStart, "<", xDeny[1] )
            aSubEnd := SubOneFromIP( xDeny[1] )
            IF ! Empty( aSubEnd ) .AND. CompareIPs( aRemainingStart, "<=", aSubEnd )
               AAdd( aTempSubs, { "type" => xAllow["type"], "start" => AClone(aRemainingStart), "end" => aSubEnd } )
            ENDIF
         ENDIF

         // Actualizar remaining a DESPUÉS del deny
         aRemainingStart := AddOneToIP( xDeny[2] )
         
         IF Empty( aRemainingStart ) .OR. CompareIPs( aRemainingStart, ">", aRemainingEnd )
            aRemainingStart := {}
            EXIT
         ENDIF
      NEXT

      // Agregar parte final si queda
      IF ! Empty( aRemainingStart ) .AND. CompareIPs( aRemainingStart, "<=", aRemainingEnd )
         AAdd( aTempSubs, { "type" => xAllow["type"], "start" => aRemainingStart, "end" => aRemainingEnd } )
      ENDIF

      AEval( aTempSubs, {|x| AAdd( aResult, x ) } )
   NEXT

RETURN MergeIntervalsDual( aResult )

// Funciones helper para operaciones de intervalos
STATIC FUNCTION OverlapsWith( aStart1, aEnd1, aStart2, aEnd2 )
RETURN !( CompareIPs( aEnd1, "<", aStart2 ) .OR. CompareIPs( aEnd2, "<", aStart1 ) )

//STATIC FUNCTION AdjacentOrOverlap( aStart1, aEnd1, aStart2 )
STATIC FUNCTION AdjacentOrOverlap( aEnd1, aStart2 )
RETURN CompareIPs( aStart2, "<=", AddOneToIP( aEnd1 ) )

STATIC FUNCTION MaxEnd( aEnd1, aEnd2 )
RETURN IIF( CompareIPs( aEnd1, "<", aEnd2 ), aEnd2, aEnd1 )

// Suma 1 a una IP (con manejo de overflow)
STATIC FUNCTION AddOneToIP( aIP )

   LOCAL aNew := AClone( aIP ), nWords := Len( aIP ), i
   LOCAL nCarry := 1

   FOR i := nWords TO 1 STEP -1
      aNew[i] += nCarry
      
      IF aNew[i] <= 0xFFFFFFFF
         nCarry := 0
         EXIT
      ENDIF
      
      aNew[i] := 0
   NEXT
   
   IF nCarry > 0 ; RETURN {} ; ENDIF
   
RETURN aNew

// Resta 1 a una IP (con manejo de underflow)
STATIC FUNCTION SubOneFromIP( aIP )

   LOCAL aNew := AClone( aIP ), nWords := Len( aIP ), i
   LOCAL nBorrow := 1

   FOR i := nWords TO 1 STEP -1
      IF aNew[i] >= nBorrow
         aNew[i] -= nBorrow
         nBorrow := 0
         EXIT
      ENDIF
      
      aNew[i] := 0xFFFFFFFF
   NEXT
   
   IF nBorrow > 0 ; RETURN {} ; ENDIF
   
RETURN aNew

// Cuenta bits a 1 en un número
STATIC FUNCTION BitCount( nNum )

   LOCAL nCount := 0, nTemp := nNum
   
   DO WHILE nTemp > 0
      nCount += hb_bitAnd( nTemp, 1 )
      nTemp := hb_bitShift( nTemp, -1 )
   ENDDO
   
RETURN nCount

// Valida que una máscara sea contigua (ej: 255.255.240.0 válida, 255.255.0.255 inválida)
STATIC FUNCTION IsValidNetmask( nMask )
   LOCAL nInverted := hb_bitXor( nMask, 0xFFFFFFFF )
   LOCAL nPlusOne := nInverted + 1
   
   // Válida si (~mask + 1) es potencia de 2 (tiene solo 1 bit a 1)
RETURN hb_bitAnd( nInverted, nPlusOne ) == 0

// Convierte array de intervalos a hash
STATIC FUNCTION ToHashDual( aIntervals )

   LOCAL hHash := {=>}
   AEval( aIntervals, {|x| hHash[ArrayToKey( x["start"] )] := x["end"] } )
   
RETURN hHash

// Convierte array a clave de string
STATIC FUNCTION ArrayToKey( aArray )

   LOCAL cKey := ""
   AEval( aArray, {|n| cKey += Str( n ) + ":" } )
   
RETURN AllTrim( cKey, , ":" )

// --- FUNCIÓN DE TEST ---

FUNCTION UTestFirewallFilter()
   LOCAL cFilter := "187.153.48.0/20 2800:810::/32 !187.153.50.0/24 !2800:810:46d::/48"
   LOCAL aFilter, lSuccess

   ? "Testing filter:", cFilter
   
   lSuccess := UParseFirewallFilter( cFilter, @aFilter, .T. )

   IF lSuccess
      ? "Parse OK. Filter ranges:"
      AEval( aFilter, {|x| QOut( x["type"], "-", Num2IP( x["start"] ), " to ", Num2IP( x["end"] ) ) } )

      // Test IPs
      ? ""
      ? "Testing IPs:"
      ? "187.153.49.100 (should allow):", IIF( UIsIPAllowed( "187.153.49.100", aFilter ), "YES", "NO" )
      ? "187.153.50.100 (should deny): ", IIF( UIsIPAllowed( "187.153.50.100", aFilter ), "YES", "NO" )
      ? "2800:810:46d:10:: (should deny):", IIF( UIsIPAllowed( "2800:810:46d:10::", aFilter ), "YES", "NO" )
      ? "2800:810:46e:: (should allow):", IIF( UIsIPAllowed( "2800:810:46e::", aFilter ), "YES", "NO" )
      ? "8.8.8.8 (should deny):", IIF( UIsIPAllowed( "8.8.8.8", aFilter ), "YES", "NO" )
      ? "187.153.63.255 (should allow):", IIF( UIsIPAllowed( "187.153.63.255", aFilter ), "YES", "NO" )
   ELSE
      ? "Parse FAILED"
   ENDIF
   
RETURN lSuccess

