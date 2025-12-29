#define CRLF                       (CHR(13)+CHR(10))
#define DEPTH_LEVEL	  8

#xcommand DEFAULT <v1> TO <x1> [, <vn> TO <xn> ] ;
=> IF <v1> == NIL ; <v1> := <x1> ; END [; IF <vn> == NIL ; <vn> := <xn> ; END ]

#xcommand TRY  => BEGIN SEQUENCE WITH {| oErr | Break( oErr ) }
#xcommand CATCH [<!oErr!>] => RECOVER [USING <oErr>] <-oErr->
#xcommand FINALLY => ALWAYS


function _d( ... )

//#ifdef __DEBUGVIEW
        #ifdef __PLATFORM__WINDOWS
		retu WAPI_OutputDebugString( MH_Out( 'dbg', ... ) )	
        #else
		retu TraceLog( MH_Out( 'dbg', ... ) )	
        #endif
//#else
//	retu ""
//#endif

//	--------------------------------------------------------- //

function _t( ... )


#ifdef __PLATFORM__WINDOWS
	retu WAPI_OutputDebugString( MH_Out( 'trace', ... ) )	
#else
	retu TraceLog( MH_Out( 'trace', ... ) )	
#endif


//	--------------------------------------------------------- //

function _w( ... ) 

retu MH_Out( 'web', ... ) 

//	--------------------------------------------------------- //

function _c( ... ) 		//	Console

retu MH_Out( 'dbg', ... ) 

//	--------------------------------------------------------- //

function MH_Out( cOut, ... )

    local cLine		:= ''
   	local nParam 	:= PCount()
	local nI
	
	for nI := 2 to nParam
	
		do case 
			case cOut == 'dbg'
				if alltrim(procname(2)) == '(b)UHTTPD2'
					cLine += procname(4) + ' (' + ltrim(str(procline(4))) + ') '
				else
					cLine += procname(2) + ' (' + ltrim(str(procline(2))) + ') '
				endif
				cLine += 'Type (' + valtype( pValue(nI) ) + ') ' + MH_ValTo( pValue(nI), nil, nil, cOut ) + CRLF	

			case cOut == 'trace'
				cLine += MH_ValTo( pValue(nI), nil, nil, cOut ) + CRLF					
				
			case cOut == 'web'				
				cLine += MH_ValTo( pValue(nI), nil, nil, cOut ) + '<br>'
				
				

		endcase
		
	next	

retu cLine

//	--------------------------------------------------------- //

static function MH_ValTo( u, nTab, nDeep, cOut )

	static _i 		:= 0
	
	local cType 	:= ValType( u )
	local cResult 	:= ""
	local hValue
	

	DEFAULT nTab TO  0
	DEFAULT nDeep TO  0
	DEFAULT cOut TO  'dbg'

	nTab++
	
	
	
	do case
		case cType == "C" .or. cType == "M"
			cResult := u
	
		case cType == "D"		; cResult := DToC( u )
		case cType == "L" 		; cResult := If( u, ".T.", ".F." )
		case cType == "N"		; cResult := AllTrim( Str( u ) )	  
		case cType == "A"		; cResult := MH_ArrayTo( @nTab, u, @nDeep, cOut )							
		case cType == "O"		
		
			hValue		:= MH_ObjToHash(u)		

			cResult 	:= MH_HashTo( @nTab, hValue, @nDeep, cOut)			
			
			//cResult 	:= MH_Valtochar( hValue )
			
		case cType == "P"   	; cResult := hb_NumToHex( u )  
		case cType == "S"		; cResult := "(Symbol)"  
		case cType == "H"		
		
			cResult := MH_HashTo( @nTab, u, @nDeep, cOut )   
		
		case cType == "T"		; cResult := hb_tstostr( u )
		case cType == "U"		; cResult := "nil"
		
		otherwise
			cResult := "Type not supported: " + cType
	endcase
 

retu cResult 

//	--------------------------------------------------------- //

static function MH_HashTo( nTab, u, nDeep, cOut )	

	local cResult 	:= ''
	local nLen 	:= len( u )	
	local n, aPair
	local cSep, cJump
	
	DEFAULT cOut TO  'dbg'
	
	do case
		case cOut == 'dbg' 
			cSep := ' '
			cJump := CRLF
		case cOut == 'trace' 
			cSep := ' '
			cJump := CRLF			
		case cOut == 'web' 
			cSep := '&nbsp;'
			cJump := '<br>'
	endcase

	nDeep++
	
	if nDeep > DEPTH_LEVEL		
		retu '<*** Too many levels ***>'
	endif


	if nLen > 0 
	
		cResult := '{' + cJump  
	
		for n := 1 to nLen			
		
			aPair := HB_HPairAt( u, n )															
			
			
			cResult += Replicate( cSep, nTab * 3 ) + 'Key: ' + aPair[1]  + ' (' + valtype(aPair[2]) + ') => ' + MH_ValTo( aPair[2], nTab, @nDeep, cOut) + cJump	
		

		next 
		
		cResult += Replicate( cSep, --nTab * 3 ) + '}'				
		
	else 	
		
		cResult := '{=>}'						
	
	endif
	
nDeep--	

retu cResult

//	--------------------------------------------------------- //

static function MH_ArrayTo( nTab, u, nDeep, cOut )	

	local cResult 	:= ''
	local nLen 	:= len( u )	
	local n 
	local cSep, cJump
	
	DEFAULT cOut TO  'dbg'
	
	do case
		case cOut == 'dbg' 
			cSep := ' '
			cJump := CRLF
		case cOut == 'trace' 
			cSep := ' '
			cJump := CRLF			
		case cOut == 'web' 
			cSep := '&nbsp;'
			cJump := '<br>'
	endcase	

	nDeep++
	
	if nDeep > DEPTH_LEVEL		
		retu '<*** Too many levels ***>'
	endif
	

	if nLen > 0 
	
		cResult := '{' + cJump  
	
		for n := 1 to nLen			

			cResult += Replicate( cSep , nTab * 3 ) + 'Type (' + valtype( u[n] ) + ') ' + MH_ValTo( u[n], nTab, @nDeep, cOut ) + cJump 

		next 
		
		cResult += Replicate( cSep, --nTab * 3 ) + '}'				
		
	else 	

		cResult := '{}'
	
	endif

	nDeep--
	
retu cResult

//	--------------------------------------------------------- //

static function MH_ObjToHash( o )

	local hObj 	:= {=>}
	local hPairs 	:= {=>} 
	
	local aDatas, aParents 
	local oError 
	
	oError := nil
	
	
	 
	try 
	
		aDatas 		:= __objGetMsgList( o, .T. )
		aParents 	:= __ClsGetAncestors( o:ClassH )
	
		AEval( aParents, { | h, n | aParents[ n ] := __ClassName( h ) } ) 
	
		hObj[ "CLASS" ] := o:ClassName()
		hObj[ "FROM" ]  := aParents 
	
		AEval( aDatas, { | cData | hPairs[ cData ] := __ObjSendMsg( o, cData ) } )
		
		hObj[ "DATAs" ]   := hPairs
		hObj[ "METHODs" ] := __objGetMsgList( o, .F. )
	
	catch oError 
	
		hObj[ 'error'] := 'Error MH_ObjToHash'		
		
	end 
	

retu hObj

//	--------------------------------------------------------- //

function _stack()
	local nI := 2
	
	DO WHILE ! EMPTY(PROCNAME(++nI))
		_d( PROCNAME(nI) + "(" + LTRIM(STR(PROCLINE(nI))) + ")"  )
	ENDDO
	
retu nil 

//	--------------------------------------------------------- //
