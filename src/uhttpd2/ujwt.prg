/* ---------------------------------------------------------
 File.......: UJWT.prg
 Description: Support to Json Web Token.
 Author.....: Carles Aubia Floresvi
 Date:......: 10/07/2019
 Usage......:
  oJWT:Encode() -> Create a new JWT
  oJWT:Decode( cJWT ) -> Decode Token. Return .T./.F.
  oJWT:SetVar( cVar, cValue ) -> Create a new var
  oJWT:GetVar( cVar ) -> Recover value var
  oJWT:GetData() -> Recover data
  oJWT:SetKey( cKey ) -> Set default server key
 --------------------------------------------------------- */
#include 'hbclass.ch'
#xcommand TRY  => BEGIN SEQUENCE WITH {| oErr | Break( oErr ) }
#xcommand CATCH [<!oErr!>] => RECOVER [USING <oErr>] <-oErr->
#xcommand FINALLY => ALWAYS

#define MSG_1 'Token error'
#define MSG_2 'Signature verify was wrong'
#define MSG_3 'Token was expired'
#define MSG_4 'Algorithm not allowed: '

CLASS UJWT

   DATA aAlgorithm     INIT { 'JWT', 'HS256' }
   DATA aHeader       INIT { => }
   DATA aPayload       INIT { => }
   DATA lClaims      INIT .T.
   DATA lValid       INIT .F.
   DATA cError       INIT ''
   DATA nLapsus      INIT 3600   // Lapsus in seconds...
   DATA cKey        INIT 'UT!2019@v1'

   METHOD New()       CONSTRUCTOR
   METHOD Reset()

   METHOD Encode()
   METHOD Decode()
   METHOD Valid()
   METHOD Refresh()      INLINE ::Encode()

   METHOD SetKey( cKey )

   METHOD SetData( hData )
   METHOD SetVar( cVar, cValue )
   METHOD SetAlgorithm( cType, cAlg )   INLINE ( ::aAlgorithm[ 1 ] := cType, ::aAlgorithm[ 2 ] := cAlg )

   METHOD SetTimeValidate( nLapsus ) INLINE if( ValType( nLapsus ) == 'N', ::nLapsus := nLapsus, nil )
   METHOD GetTimeValidate()    INLINE hb_HGetDef( ::aPayLoad, 'lap', ::nLapsus )

   METHOD GetVar( cVar, uDefault )
   METHOD GetExp()      // Exp = Expires

   METHOD MakeSignature( cHeader, cPayload )

   METHOD GetData()
   METHOD GetClaims()
   METHOD GetError()      INLINE ::cError

ENDCLASS

// ----------------------------------------------- //

METHOD New( cKey ) CLASS UJWT

   ::SetKey( cKey )

   ::aPayload[ 'iss'  ] := 'UT'    // Emisor

   RETU SELF

// ----------------------------------------------- //

METHOD SetKey( cKey ) CLASS UJWT

   hb_default( @cKey, '' )

   IF !Empty( cKey )
      ::cKey := cKey
   ENDIF

   RETU NIL

// ----------------------------------------------- //

METHOD Encode( hData ) CLASS UJWT

   LOCAL cHeader, cPayload, cSignature
   LOCAL cJWT, nDateTime

// Valid Algorithm. At the moment we're working in this method...

   ::aHeader[ 'typ' ] := ::aAlgorithm[ 1 ]
   ::aHeader[ 'alg' ] := ::aAlgorithm[ 2 ]

   IF !( ::aHeader[ 'typ' ] == 'JWT' .AND. ::aHeader[ 'alg' ] == 'HS256' )
      ::cError := MSG_4 + ::aHeader[ 'typ' ] + '/' + ::aHeader[ 'alg' ]
      RETU ''
   ENDIF

// Set data

   ::SetData( hData )

// Actualizamos fecha de expiracion (CLAIMS)

   IF ::lClaims

      nDateTime  := hb_DateTime()

      ::aPayload[ 'iat'  ] := hb_TToSec( nDateTime )

      IF ::nLapsus == 0
         ::aPayload[ 'exp'  ] := 0      // Expire
      ELSE
         ::aPayload[ 'exp'  ] := hb_TToSec( nDateTime ) + ::nLapsus  // Expire
      ENDIF

      ::aPayload[ 'lap'  ] := ::nLapsus     // lapsus
   ENDIF


// Codificamos Header y Payload

   cHeader     := hb_jsonEncode( ::aHeader )
   cHeader     := hb_base64Encode( cHeader )
   cHeader  := hb_StrReplace( cHeader, '+/=', { '-', '_', '' } )

// cPayload   := hb_serialize( ::aPayload )
   cPayload   := hb_jsonEncode( ::aPayload )
   cPayload    := hb_base64Encode( cPayload )
   cPayload   := hb_StrReplace( cPayload, '+/=', { '-', '_', '' } )

// Make signature

   cSignature := ::MakeSignature( cHeader, cPayload )

// Make JWT

   cJWT := cHeader + '.' + cPayload + '.' + cSignature

   RETU cJWT

// ----------------------------------------------- //

METHOD Reset() CLASS UJWT

   ::aHeader  := { => }
   ::aPayload := { => }
   ::cError := ''

   RETU NIL

// ----------------------------------------------- //

METHOD Valid( cJWT ) CLASS UJWT

   LOCAL aJWT, cSignature, cNewSignature

   ::lValid  := .F.

// Antes de decodificar reseteamos datas

   ::Reset()

// Una firma JWT consta de 3 parte separadas por "."

   aJWT := hb_ATokens( cJWT, '.' )

   IF !( Len( aJWT ) ==  3 )
      ::cError := MSG_1
      RETU .F.
   ENDIF

// Recuperamos datos del Header

   ::aHeader  := hb_StrReplace( aJWT[ 1 ], "-_", "+/" )
   ::aHeader  := hb_base64Decode( ::aHeader )
   ::aHeader  := hb_jsonDecode( ::aHeader )

   IF !HB_ISHASH( ::aHeader ) .OR. ! hb_HHasKey( ::aHeader, 'typ' ) .OR. ! hb_HHasKey( ::aHeader, 'alg' )
      ::cError := MSG_1
      RETU .F.
   ENDIF


// Recuperamos datos del PayLoad

   ::aPayload := hb_StrReplace( aJWT[ 2 ], "-_", "+/" )
   ::aPayload := hb_base64Decode( ::aPayload )
   ::aPayload := hb_jsonDecode( ::aPayload )

// Recuperamos Firma

   cSignature  := aJWT[ 3 ]

// Creamos una firma nueva para validar que es la misma que hemos recuperado

   cNewSignature := ::MakeSignature( aJWT[ 1 ], aJWT[ 2 ] )

   ::lValid := ( cSignature == cNewSignature )

   IF ! ::lValid
      ::cError := MSG_2
      RETU .F.
   ENDIF

// Validamos 'exp' (JWT Claims)

   IF ::lClaims .AND. hb_HHasKey( ::aPayLoad, 'exp' )

      IF ::aPayLoad[ 'exp' ] > 0

         IF  hb_TToSec(  hb_DateTime() ) > ::aPayLoad[ 'exp' ]
            ::cError := MSG_3
            RETU .F.
         ENDIF
      ENDIF
   ENDIF

   RETU ::lValid

// ----------------------------------------------- //

METHOD Decode( cJWT ) CLASS UJWT

   IF ! ::Valid( cJWT )
      RETU NIL
   ENDIF

   RETU ::GetData()

// ----------------------------------------------- //

METHOD GetData( lClaims ) CLASS UJWT

   LOCAL hData

   __defaultNIL( @lClaims, .F. )

   IF !::lValid
      RETU NIL
   ENDIF

   IF lClaims
      RETU ::aPayLoad
   ELSE
      hData := hb_HClone( ::aPayLoad )
      hb_HDel( hData, 'exp' )
      hb_HDel( hData, 'iss' )
      hb_HDel( hData, 'lap' )
      hb_HDel( hData, 'iat' )
      RETU hData
   ENDIF

   RETU NIL

// ----------------------------------------------- //

METHOD SetData( hData ) CLASS UJWT

   LOCAL nI, h

   IF ValType( hData ) == 'H'

      FOR nI := 1 TO Len( hData )
         h := hb_HPairAt( hData, nI )
         ::SetVar( h[ 1 ], h[ 2 ] )
      NEXT

   ENDIF

   RETU NIL

// ----------------------------------------------- //

METHOD GetClaims() CLASS UJWT

   LOCAL hData := { => }

   hData[ 'iss' ] := ::aPayLoad[ 'iss' ]
   hData[ 'exp' ] := ::aPayLoad[ 'exp' ]
   hData[ 'iat' ] := ::aPayLoad[ 'iat' ]
   hData[ 'lap' ] := ::aPayLoad[ 'lap' ]

   RETU hData


// ----------------------------------------------- //

METHOD SetVar( cVar, uValue ) CLASS UJWT

   __defaultNIL( @cVar, '' )

   cVar := AllTrim( Lower( cVar ) )

// Xec Claims var

// IF  cVar == 'exp' .or. cVar == 'iss' .or. cVar == 'lap' .or. cVar == 'iat'
   IF  cVar == 'exp' .OR. cVar == 'lap' .OR. cVar == 'iat'
      RETU NIL
   ENDIF

// Set var

   ::aPayload[ cVar ] := uValue

   RETU NIL

// ----------------------------------------------- //

METHOD GetVar( cVar ) CLASS UJWT

   LOCAL uValue := ''

   __defaultNIL( @cVar, '' )

   cVar := AllTrim( Lower( cVar ) )

   RETU hb_HGetDef( ::aPayLoad, cVar, '' )

// ----------------------------------------------- //

METHOD GetExp() CLASS UJWT    // Exp = Expire.... Por efecto devolveremos el default de la clase

   RETU ::Getvar( 'exp', ::nLapsus )

// ----------------------------------------------- //

METHOD MakeSignature( cHeader, cPayload ) CLASS UJWT

   LOCAL cSignature := ''

// Make signature

   DO CASE
   CASE ::aHeader[ 'typ' ] == 'JWT' .AND. ::aHeader[ 'alg' ] == 'HS256'
      cSignature := hb_HMAC_SHA256( ( cHeader + '.' + cPayload ), ::cKey )

   ENDCASE

   cSignature  := ToString( cSignature )
   cSignature  := hb_base64Encode( cSignature )
   cSignature  := hb_StrReplace( cSignature, '+/=', { '-', '_', '' } )

   RETU cSignature

// ----------------------------------------------- //

STATIC FUNCTION ToString( cData )

   LOCAL cString  := ""
   LOCAL nLen   := Len( cData )
   LOCAL nX, nNum

   cData := Upper( cData )

   FOR nX := 1 TO nLen STEP 2
      nNum   := ( At( SubStr( cData, nX, 1 ), "0123456789ABCDEF" ) - 1 ) * 16
      nNum   += At( SubStr( cData, nX + 1, 1 ), "0123456789ABCDEF" ) - 1
      cString  += Chr( nNum )
   NEXT

   RETU cString
