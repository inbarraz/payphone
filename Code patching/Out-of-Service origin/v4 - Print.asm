
	CPU		1805

	INCL      "1805reg.asm"

;==============================
;
; RAM locations

ptrNewString	EQU		$9E00
ptrString		EQU		$9F00
storeR7			EQU		$9F10

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
	RLDI		RC, str4648		; String pointer
	LBR			Overwrite		; SaveRegisters
str4648:
	db			"4648",0

Origin_46aa:
	RLDI		RC, str46AA		; String pointer
	LBR			Overwrite		; SaveRegisters
str46AA:
	db  		"46AA",0

Origin_46bf:
	RLDI		RC, str46BF		; String pointer
	LBR			Overwrite		; SaveRegisters
str46BF:
	db  		"46BF",0

Origin_46d8:
	RLDI		RC, str46D8		; String pointer
	LBR			Overwrite		; SaveRegisters
str46D8:
	db  		"46D8",0

Origin_4723:
	RLDI		RC, str4723		; String pointer
	LBR			Overwrite		; SaveRegisters
str4723:
	db  		"4723",0

Origin_4756:
	RLDI		RC, str4756		; String pointer
	LBR			Overwrite		; SaveRegisters
str4756:
	db  		"4756",0

Origin_480f:
	RLDI		RC, str480F		; String pointer
	LBR			Overwrite		; SaveRegisters
str480F:
	db  		"480F",0

Origin_4824:
	RLDI		RC, str4824		; String pointer
	LBR			Overwrite		; SaveRegisters
str4824:
	db  		"4824",0

Origin_484a:
	RLDI		RC, str484A		; String pointer
	LBR			Overwrite		; SaveRegisters
str484A:
	db  		"484A",0

Origin_4930:
	RLDI		RC, str4930		; String pointer
	LBR			Overwrite		; SaveRegisters
str4930:
	db  		"4930",0

Origin_4957:
	RLDI		RC, str4957		; String pointer
	LBR			Overwrite		; SaveRegisters
str4957:
	db  		"4957",0

Origin_6f91:
	RLDI		RC, str6F91		; String pointer
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

	LBR 		$48A9 			; Print_Out_of_Service

; ========================================
; 
; PATCH #2: REPLACE THE TEXT FOR PRINTING

		ORG 	$7B00

Patch2_entry:

; Start by performing the original code, to keep order (eg. R(X))

	RLXA		RE				; Original string address
	SEX			$02

; Only operate on English strings (R5 = 0)

	GLO			R5
	XRI			$00
	LBNZ		Patch2_exit

; Now overwrite data: Use R5 as pointer to load RE, then set R5
; Get the string pointer from RAM, stored by Patch1
; In the meantime, use this patch

; First, copy the base string to RAM

; We need an extra register for counter. R7 is used so we know it's not the PC

	RLDI		R5, storeR7
	GHI 		R7
	STR 		R5
	INC 		R5
	GLO 		R7
	STR 		R5

; Copy the string

	RLDI		R5, Base_string 	; Base_string
	RLDI		RE, ptrNewString	; RAM location for our string
	RLDI 		R7, $0011

CopyLoop1:

	LDA 		R5
	STR			RE
	INC 		RE
	DBNZ 		R7, CopyLoop1

; Second, overwrite the ZZZZ with our address

	RLDI		RE, ptrString 		; Pointer to string to copy
	LDA 		RE
	PHI 		R5
	LDN 		RE
	PLO 		R5

	RLDI		RE, (ptrNewString + (Address_string - Base_string)) ; Pointer to the "ZZZZ"
	RLDI 		R7, $0004

CopyLoop2:

	LDA 		R5
	STR			RE
	INC 		RE
	DBNZ 		R7, CopyLoop2

; Restore R7

	RLDI		R5, storeR7
	LDA 		R5
	PHI 		R7
	LDN 		R5
	PLO 		R7

; Third, put the string address in RE and modifier length in R5 

	RLDI 		RE, ptrNewString
	RLDI 		R5, 0000

; Jump back to original code

Patch2_exit:

	LBR 		$27D6

Base_string:
	db		"Address‮ is‮ "
Address_string:
	db		"ZZZZ.",0

	END