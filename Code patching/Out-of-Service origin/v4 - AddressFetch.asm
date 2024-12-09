
	CPU		1805

	INCL      "1805reg.asm"

;==============================
;
; RAM locations

ptrString		EQU		$9F00

; ========================================
; 
; PATCH #1: SET THE OUTPUT STRING POINTER

		ORG 	$7A00

Origin_460a:
	RLDI		RC, str460a		; String pointer
	LBR			Overwrite		; SaveRegisters
str460a:		
	db			"460A",0

Origin_4648:
	RLDI		RC, str4648	; String pointer
	LBR			Overwrite		; SaveRegisters
str4648:
	db		"4648",0

Origin_46aa:
	RLDI		RC, str46AA	; String pointer
	LBR			Overwrite		; SaveRegisters
str46AA:
	db  		"46AA",0

Origin_46bf:
	RLDI		RC, str46BF	; String pointer
	LBR			Overwrite		; SaveRegisters
str46BF:
	db  		"46BF",0

Origin_46d8:
	RLDI		RC, str46D8	; String pointer
	LBR			Overwrite		; SaveRegisters
str46D8:
	db  		"46D8",0

Origin_4723:
	RLDI		RC, str4723	; String pointer
	LBR			Overwrite		; SaveRegisters
str4723:
	db  		"4723",0

Origin_4756:
	RLDI		RC, str4756	; String pointer
	LBR			Overwrite		; SaveRegisters
str4756:
	db  		"4756",0

Origin_480f:
	RLDI		RC, str480F	; String pointer
	LBR			Overwrite		; SaveRegisters
str480F:
	db  		"480F",0

Origin_4824:
	RLDI		RC, str4824	; String pointer
	LBR			Overwrite		; SaveRegisters
str4824:
	db  		"4824",0

Origin_484a:
	RLDI		RC, str484A	; String pointer
	LBR			Overwrite		; SaveRegisters
str484A:
	db  		"484A",0

Origin_4930:
	RLDI		RC, str4930	; String pointer
	LBR			Overwrite		; SaveRegisters
str4930:
	db  		"4930",0

Origin_4957:
	RLDI		RC, str4957	; String pointer
	LBR			Overwrite		; SaveRegisters
str4957:
	db  		"4957",0

Origin_6f91:
	RLDI		RC, str6F91	; String pointer
	LBR			Overwrite		; SaveRegisters
str6F91:
	db  		"6F91",0

Overwrite:

	RLDI		R7, ptrString	; R7 = Destination, RC = Value
	GHI			RC
	STR 		R7
	INC 		R7
	GLO 		RC
	STR 		R7

Return:

	LBR 		$48A9 		; Print_Out_of_Service

	END