
challenge:     file format elf64-x86-64


Disassembly of section .interp:

0000000000400200 <.interp>:
  400200:	2f                   	(bad)  
  400201:	6c                   	insb   (%dx),%es:(%rdi)
  400202:	69 62 36 34 2f 6c 64 	imul   $0x646c2f34,0x36(%rdx),%esp
  400209:	2d 6c 69 6e 75       	sub    $0x756e696c,%eax
  40020e:	78 2d                	js     40023d <_init-0x77b>
  400210:	78 38                	js     40024a <_init-0x76e>
  400212:	36                   	ss
  400213:	2d 36 34 2e 73       	sub    $0x732e3436,%eax
  400218:	6f                   	outsl  %ds:(%rsi),(%dx)
  400219:	2e 32 00             	xor    %cs:(%rax),%al

Disassembly of section .note.ABI-tag:

000000000040021c <.note.ABI-tag>:
  40021c:	04 00                	add    $0x0,%al
  40021e:	00 00                	add    %al,(%rax)
  400220:	10 00                	adc    %al,(%rax)
  400222:	00 00                	add    %al,(%rax)
  400224:	01 00                	add    %eax,(%rax)
  400226:	00 00                	add    %al,(%rax)
  400228:	47                   	rex.RXB
  400229:	4e 55                	rex.WRX push %rbp
  40022b:	00 00                	add    %al,(%rax)
  40022d:	00 00                	add    %al,(%rax)
  40022f:	00 02                	add    %al,(%rdx)
  400231:	00 00                	add    %al,(%rax)
  400233:	00 06                	add    %al,(%rsi)
  400235:	00 00                	add    %al,(%rax)
  400237:	00 20                	add    %ah,(%rax)
  400239:	00 00                	add    %al,(%rax)
	...

Disassembly of section .dynsym:

0000000000400240 <.dynsym>:
	...
  400258:	01 00                	add    %eax,(%rax)
  40025a:	00 00                	add    %al,(%rax)
  40025c:	12 00                	adc    (%rax),%al
	...
  40026e:	00 00                	add    %al,(%rax)
  400270:	29 00                	sub    %eax,(%rax)
  400272:	00 00                	add    %al,(%rax)
  400274:	12 00                	adc    (%rax),%al
	...
  400286:	00 00                	add    %al,(%rax)
  400288:	30 00                	xor    %al,(%rax)
  40028a:	00 00                	add    %al,(%rax)
  40028c:	12 00                	adc    (%rax),%al
	...
  40029e:	00 00                	add    %al,(%rax)
  4002a0:	39 00                	cmp    %eax,(%rax)
  4002a2:	00 00                	add    %al,(%rax)
  4002a4:	20 00                	and    %al,(%rax)
	...
  4002b6:	00 00                	add    %al,(%rax)
  4002b8:	48 00 00             	rex.W add %al,(%rax)
  4002bb:	00 12                	add    %dl,(%rdx)
	...
  4002cd:	00 00                	add    %al,(%rax)
  4002cf:	00 4f 00             	add    %cl,0x0(%rdi)
  4002d2:	00 00                	add    %al,(%rax)
  4002d4:	12 00                	adc    (%rax),%al
  4002d6:	0a 00                	or     (%rax),%al
  4002d8:	b8 09 40 00 00       	mov    $0x4009,%eax
	...
  4002e5:	00 00                	add    %al,(%rax)
  4002e7:	00 55 00             	add    %dl,0x0(%rbp)
  4002ea:	00 00                	add    %al,(%rax)
  4002ec:	12 00                	adc    (%rax),%al
	...
  4002fe:	00 00                	add    %al,(%rax)
  400300:	5c                   	pop    %rsp
  400301:	00 00                	add    %al,(%rax)
  400303:	00 12                	add    %dl,(%rdx)
	...
  400315:	00 00                	add    %al,(%rax)
  400317:	00 64 00 00          	add    %ah,0x0(%rax,%rax,1)
  40031b:	00 12                	add    %dl,(%rdx)
  40031d:	00 0d 00 34 12 40    	add    %cl,0x40123400(%rip)        # 40523723 <_end+0x40120c1b>
	...
  40032f:	00 6a 00             	add    %ch,0x0(%rdx)
  400332:	00 00                	add    %al,(%rax)
  400334:	12 00                	adc    (%rax),%al
	...
  400346:	00 00                	add    %al,(%rax)
  400348:	71 00                	jno    40034a <_init-0x66e>
  40034a:	00 00                	add    %al,(%rax)
  40034c:	20 00                	and    %al,(%rax)
	...
  40035e:	00 00                	add    %al,(%rax)
  400360:	8d 00                	lea    (%rax),%eax
  400362:	00 00                	add    %al,(%rax)
  400364:	20 00                	and    %al,(%rax)
	...
  400376:	00 00                	add    %al,(%rax)
  400378:	a7                   	cmpsl  %es:(%rdi),%ds:(%rsi)
  400379:	00 00                	add    %al,(%rax)
  40037b:	00 20                	add    %ah,(%rax)
	...
  40038d:	00 00                	add    %al,(%rax)
  40038f:	00 bb 00 00 00 12    	add    %bh,0x12000000(%rbx)
	...
  4003a5:	00 00                	add    %al,(%rax)
  4003a7:	00 c1                	add    %al,%cl
  4003a9:	00 00                	add    %al,(%rax)
  4003ab:	00 12                	add    %dl,(%rdx)
	...
  4003bd:	00 00                	add    %al,(%rax)
  4003bf:	00 ce                	add    %cl,%dh
  4003c1:	00 00                	add    %al,(%rax)
  4003c3:	00 12                	add    %dl,(%rdx)
	...
  4003d5:	00 00                	add    %al,(%rax)
  4003d7:	00 d3                	add    %dl,%bl
  4003d9:	00 00                	add    %al,(%rax)
  4003db:	00 12                	add    %dl,(%rdx)
	...
  4003ed:	00 00                	add    %al,(%rax)
  4003ef:	00 dc                	add    %bl,%ah
  4003f1:	00 00                	add    %al,(%rax)
  4003f3:	00 12                	add    %dl,(%rdx)
	...
  400405:	00 00                	add    %al,(%rax)
  400407:	00 f3                	add    %dh,%bl
  400409:	00 00                	add    %al,(%rax)
  40040b:	00 12                	add    %dl,(%rdx)
	...
  40041d:	00 00                	add    %al,(%rax)
  40041f:	00 07                	add    %al,(%rdi)
  400421:	01 00                	add    %eax,(%rax)
  400423:	00 12                	add    %dl,(%rdx)
	...
  400435:	00 00                	add    %al,(%rax)
  400437:	00 1b                	add    %bl,(%rbx)
  400439:	01 00                	add    %eax,(%rax)
  40043b:	00 12                	add    %dl,(%rdx)
	...
  40044d:	00 00                	add    %al,(%rax)
  40044f:	00 2e                	add    %ch,(%rsi)
  400451:	01 00                	add    %eax,(%rax)
  400453:	00 12                	add    %dl,(%rdx)
	...
  400465:	00 00                	add    %al,(%rax)
  400467:	00 40 01             	add    %al,0x1(%rax)
  40046a:	00 00                	add    %al,(%rax)
  40046c:	12 00                	adc    (%rax),%al
	...
  40047e:	00 00                	add    %al,(%rax)
  400480:	50                   	push   %rax
  400481:	01 00                	add    %eax,(%rax)
  400483:	00 12                	add    %dl,(%rdx)
	...
  400495:	00 00                	add    %al,(%rax)
  400497:	00 55 01             	add    %dl,0x1(%rbp)
  40049a:	00 00                	add    %al,(%rax)
  40049c:	12 00                	adc    (%rax),%al
	...
  4004ae:	00 00                	add    %al,(%rax)
  4004b0:	67 01 00             	add    %eax,(%eax)
  4004b3:	00 10                	add    %dl,(%rax)
  4004b5:	00 f1                	add    %dh,%cl
  4004b7:	ff                   	(bad)  
  4004b8:	f8                   	clc    
  4004b9:	2a 40 00             	sub    0x0(%rax),%al
	...
  4004c8:	73 01                	jae    4004cb <_init-0x4ed>
  4004ca:	00 00                	add    %al,(%rax)
  4004cc:	10 00                	adc    %al,(%rax)
  4004ce:	f1                   	icebp  
  4004cf:	ff                   	(bad)  
  4004d0:	f8                   	clc    
  4004d1:	2a 40 00             	sub    0x0(%rax),%al
	...
  4004e0:	7a 01                	jp     4004e3 <_init-0x4d5>
  4004e2:	00 00                	add    %al,(%rax)
  4004e4:	10 00                	adc    %al,(%rax)
  4004e6:	f1                   	icebp  
  4004e7:	ff 08                	decl   (%rax)
  4004e9:	2b 40 00             	sub    0x0(%rax),%eax
	...

Disassembly of section .dynstr:

00000000004004f8 <.dynstr>:
  4004f8:	00 5f 5f             	add    %bl,0x5f(%rdi)
  4004fb:	6c                   	insb   (%dx),%es:(%rdi)
  4004fc:	69 62 63 5f 73 74 61 	imul   $0x6174735f,0x63(%rdx),%esp
  400503:	72 74                	jb     400579 <_init-0x43f>
  400505:	5f                   	pop    %rdi
  400506:	6d                   	insl   (%dx),%es:(%rdi)
  400507:	61                   	(bad)  
  400508:	69 6e 00 47 4c 49 42 	imul   $0x42494c47,0x0(%rsi),%ebp
  40050f:	43 5f                	rex.XB pop %r15
  400511:	32 2e                	xor    (%rsi),%ch
  400513:	32 2e                	xor    (%rsi),%ch
  400515:	35 00 6c 69 62       	xor    $0x62696c00,%eax
  40051a:	63 2e                	movslq (%rsi),%ebp
  40051c:	73 6f                	jae    40058d <_init-0x42b>
  40051e:	2e 36 00 70 65       	cs add %dh,%cs:%ss:0x65(%rax)
  400523:	72 72                	jb     400597 <_init-0x421>
  400525:	6f                   	outsl  %ds:(%rsi),(%dx)
  400526:	72 00                	jb     400528 <_init-0x490>
  400528:	6d                   	insl   (%dx),%es:(%rdi)
  400529:	70 72                	jo     40059d <_init-0x41b>
  40052b:	6f                   	outsl  %ds:(%rsi),(%dx)
  40052c:	74 65                	je     400593 <_init-0x425>
  40052e:	63 74 00 5f          	movslq 0x5f(%rax,%rax,1),%esi
  400532:	5f                   	pop    %rdi
  400533:	67 6d                	insl   (%dx),%es:(%edi)
  400535:	6f                   	outsl  %ds:(%rsi),(%dx)
  400536:	6e                   	outsb  %ds:(%rsi),(%dx)
  400537:	5f                   	pop    %rdi
  400538:	73 74                	jae    4005ae <_init-0x40a>
  40053a:	61                   	(bad)  
  40053b:	72 74                	jb     4005b1 <_init-0x407>
  40053d:	5f                   	pop    %rdi
  40053e:	5f                   	pop    %rdi
  40053f:	00 70 74             	add    %dh,0x74(%rax)
  400542:	72 61                	jb     4005a5 <_init-0x413>
  400544:	63 65 00             	movslq 0x0(%rbp),%esp
  400547:	5f                   	pop    %rdi
  400548:	69 6e 69 74 00 70 72 	imul   $0x72700074,0x69(%rsi),%ebp
  40054f:	69 6e 74 66 00 73 79 	imul   $0x79730066,0x74(%rsi),%ebp
  400556:	73 63                	jae    4005bb <_init-0x3fd>
  400558:	6f                   	outsl  %ds:(%rsi),(%dx)
  400559:	6e                   	outsb  %ds:(%rsi),(%dx)
  40055a:	66                   	data16
  40055b:	00 5f 66             	add    %bl,0x66(%rdi)
  40055e:	69 6e 69 00 73 69 67 	imul   $0x67697300,0x69(%rsi),%ebp
  400565:	6e                   	outsb  %ds:(%rsi),(%dx)
  400566:	61                   	(bad)  
  400567:	6c                   	insb   (%dx),%es:(%rdi)
  400568:	00 5f 49             	add    %bl,0x49(%rdi)
  40056b:	54                   	push   %rsp
  40056c:	4d 5f                	rex.WRB pop %r15
  40056e:	64                   	fs
  40056f:	65                   	gs
  400570:	72 65                	jb     4005d7 <_init-0x3e1>
  400572:	67 69 73 74 65 72 54 	imul   $0x4d547265,0x74(%ebx),%esi
  400579:	4d 
  40057a:	43 6c                	rex.XB insb (%dx),%es:(%rdi)
  40057c:	6f                   	outsl  %ds:(%rsi),(%dx)
  40057d:	6e                   	outsb  %ds:(%rsi),(%dx)
  40057e:	65                   	gs
  40057f:	54                   	push   %rsp
  400580:	61                   	(bad)  
  400581:	62                   	(bad)  
  400582:	6c                   	insb   (%dx),%es:(%rdi)
  400583:	65 00 5f 49          	add    %bl,%gs:0x49(%rdi)
  400587:	54                   	push   %rsp
  400588:	4d 5f                	rex.WRB pop %r15
  40058a:	72 65                	jb     4005f1 <_init-0x3c7>
  40058c:	67 69 73 74 65 72 54 	imul   $0x4d547265,0x74(%ebx),%esi
  400593:	4d 
  400594:	43 6c                	rex.XB insb (%dx),%es:(%rdi)
  400596:	6f                   	outsl  %ds:(%rsi),(%dx)
  400597:	6e                   	outsb  %ds:(%rsi),(%dx)
  400598:	65                   	gs
  400599:	54                   	push   %rsp
  40059a:	61                   	(bad)  
  40059b:	62                   	(bad)  
  40059c:	6c                   	insb   (%dx),%es:(%rdi)
  40059d:	65 00 5f 4a          	add    %bl,%gs:0x4a(%rdi)
  4005a1:	76 5f                	jbe    400602 <_init-0x3b6>
  4005a3:	52                   	push   %rdx
  4005a4:	65 67 69 73 74 65 72 	imul   $0x6c437265,%gs:0x74(%ebx),%esi
  4005ab:	43 6c 
  4005ad:	61                   	(bad)  
  4005ae:	73 73                	jae    400623 <_init-0x395>
  4005b0:	65                   	gs
  4005b1:	73 00                	jae    4005b3 <_init-0x405>
  4005b3:	61                   	(bad)  
  4005b4:	6c                   	insb   (%dx),%es:(%rdi)
  4005b5:	61                   	(bad)  
  4005b6:	72 6d                	jb     400625 <_init-0x393>
  4005b8:	00 67 65             	add    %ah,0x65(%rdi)
  4005bb:	74 74                	je     400631 <_init-0x387>
  4005bd:	69 6d 65 6f 66 64 61 	imul   $0x6164666f,0x65(%rbp),%ebp
  4005c4:	79 00                	jns    4005c6 <_init-0x3f2>
  4005c6:	65                   	gs
  4005c7:	78 69                	js     400632 <_init-0x386>
  4005c9:	74 00                	je     4005cb <_init-0x3ed>
  4005cb:	6d                   	insl   (%dx),%es:(%rdi)
  4005cc:	65                   	gs
  4005cd:	6d                   	insl   (%dx),%es:(%rdi)
  4005ce:	61                   	(bad)  
  4005cf:	6c                   	insb   (%dx),%es:(%rdi)
  4005d0:	69 67 6e 00 45 56 50 	imul   $0x50564500,0x6e(%rdi),%esp
  4005d7:	5f                   	pop    %rdi
  4005d8:	43                   	rex.XB
  4005d9:	49 50                	rex.WB push %r8
  4005db:	48                   	rex.W
  4005dc:	45 52                	rex.RB push %r10
  4005de:	5f                   	pop    %rdi
  4005df:	43 54                	rex.XB push %r12
  4005e1:	58                   	pop    %rax
  4005e2:	5f                   	pop    %rdi
  4005e3:	63 6c 65 61          	movslq 0x61(%rbp,%riz,2),%ebp
  4005e7:	6e                   	outsb  %ds:(%rsi),(%dx)
  4005e8:	75 70                	jne    40065a <_init-0x35e>
  4005ea:	00 45 56             	add    %al,0x56(%rbp)
  4005ed:	50                   	push   %rax
  4005ee:	5f                   	pop    %rdi
  4005ef:	43                   	rex.XB
  4005f0:	49 50                	rex.WB push %r8
  4005f2:	48                   	rex.W
  4005f3:	45 52                	rex.RB push %r10
  4005f5:	5f                   	pop    %rdi
  4005f6:	43 54                	rex.XB push %r12
  4005f8:	58                   	pop    %rax
  4005f9:	5f                   	pop    %rdi
  4005fa:	69 6e 69 74 00 45 56 	imul   $0x56450074,0x69(%rsi),%ebp
  400601:	50                   	push   %rax
  400602:	5f                   	pop    %rdi
  400603:	44                   	rex.R
  400604:	65 63 72 79          	movslq %gs:0x79(%rdx),%esi
  400608:	70 74                	jo     40067e <_init-0x33a>
  40060a:	46 69 6e 61 6c 5f 65 	rex.RX imul $0x78655f6c,0x61(%rsi),%r13d
  400611:	78 
  400612:	00 45 56             	add    %al,0x56(%rbp)
  400615:	50                   	push   %rax
  400616:	5f                   	pop    %rdi
  400617:	44                   	rex.R
  400618:	65 63 72 79          	movslq %gs:0x79(%rdx),%esi
  40061c:	70 74                	jo     400692 <_init-0x326>
  40061e:	49 6e                	rex.WB outsb %ds:(%rsi),(%dx)
  400620:	69 74 5f 65 78 00 45 	imul   $0x56450078,0x65(%rdi,%rbx,2),%esi
  400627:	56 
  400628:	50                   	push   %rax
  400629:	5f                   	pop    %rdi
  40062a:	44                   	rex.R
  40062b:	65 63 72 79          	movslq %gs:0x79(%rdx),%esi
  40062f:	70 74                	jo     4006a5 <_init-0x313>
  400631:	55                   	push   %rbp
  400632:	70 64                	jo     400698 <_init-0x320>
  400634:	61                   	(bad)  
  400635:	74 65                	je     40069c <_init-0x31c>
  400637:	00 45 56             	add    %al,0x56(%rbp)
  40063a:	50                   	push   %rax
  40063b:	5f                   	pop    %rdi
  40063c:	61                   	(bad)  
  40063d:	65                   	gs
  40063e:	73 5f                	jae    40069f <_init-0x319>
  400640:	31 32                	xor    %esi,(%rdx)
  400642:	38 5f 6f             	cmp    %bl,0x6f(%rdi)
  400645:	66                   	data16
  400646:	62                   	(bad)  
  400647:	00 53 48             	add    %dl,0x48(%rbx)
  40064a:	41 31 00             	xor    %eax,(%r8)
  40064d:	6d                   	insl   (%dx),%es:(%rdi)
  40064e:	65                   	gs
  40064f:	6d                   	insl   (%dx),%es:(%rdi)
  400650:	63 70 79             	movslq 0x79(%rax),%esi
  400653:	00 47 4c             	add    %al,0x4c(%rdi)
  400656:	49                   	rex.WB
  400657:	42                   	rex.X
  400658:	43 5f                	rex.XB pop %r15
  40065a:	32 2e                	xor    (%rsi),%ch
  40065c:	31 34 00             	xor    %esi,(%rax,%rax,1)
  40065f:	5f                   	pop    %rdi
  400660:	5f                   	pop    %rdi
  400661:	62                   	(bad)  
  400662:	73 73                	jae    4006d7 <_init-0x2e1>
  400664:	5f                   	pop    %rdi
  400665:	73 74                	jae    4006db <_init-0x2dd>
  400667:	61                   	(bad)  
  400668:	72 74                	jb     4006de <_init-0x2da>
  40066a:	00 5f 65             	add    %bl,0x65(%rdi)
  40066d:	64                   	fs
  40066e:	61                   	(bad)  
  40066f:	74 61                	je     4006d2 <_init-0x2e6>
  400671:	00 5f 65             	add    %bl,0x65(%rdi)
  400674:	6e                   	outsb  %ds:(%rsi),(%dx)
  400675:	64 00 6c 69 62       	add    %ch,%fs:0x62(%rcx,%rbp,2)
  40067a:	63 72 79             	movslq 0x79(%rdx),%esi
  40067d:	70 74                	jo     4006f3 <_init-0x2c5>
  40067f:	6f                   	outsl  %ds:(%rsi),(%dx)
  400680:	2e 73 6f             	jae,pn 4006f2 <_init-0x2c6>
  400683:	2e 31 2e             	xor    %ebp,%cs:(%rsi)
  400686:	30 2e                	xor    %ch,(%rsi)
  400688:	30 00                	xor    %al,(%rax)

Disassembly of section .hash:

0000000000400690 <.hash>:
  400690:	11 00                	adc    %eax,(%rax)
  400692:	00 00                	add    %al,(%rax)
  400694:	1d 00 00 00 00       	sbb    $0x0,%eax
  400699:	00 00                	add    %al,(%rax)
  40069b:	00 1b                	add    %bl,(%rbx)
  40069d:	00 00                	add    %al,(%rax)
  40069f:	00 17                	add    %dl,(%rdi)
  4006a1:	00 00                	add    %al,(%rax)
  4006a3:	00 0d 00 00 00 00    	add    %cl,0x0(%rip)        # 4006a9 <_init-0x30f>
  4006a9:	00 00                	add    %al,(%rax)
  4006ab:	00 00                	add    %al,(%rax)
  4006ad:	00 00                	add    %al,(%rax)
  4006af:	00 11                	add    %dl,(%rcx)
  4006b1:	00 00                	add    %al,(%rax)
  4006b3:	00 18                	add    %bl,(%rax)
  4006b5:	00 00                	add    %al,(%rax)
  4006b7:	00 19                	add    %bl,(%rcx)
  4006b9:	00 00                	add    %al,(%rax)
  4006bb:	00 06                	add    %al,(%rsi)
  4006bd:	00 00                	add    %al,(%rax)
  4006bf:	00 07                	add    %al,(%rdi)
  4006c1:	00 00                	add    %al,(%rax)
  4006c3:	00 1a                	add    %bl,(%rdx)
  4006c5:	00 00                	add    %al,(%rax)
  4006c7:	00 15 00 00 00 1c    	add    %dl,0x1c000000(%rip)        # 1c4006cd <_end+0x1bffdbc5>
  4006cd:	00 00                	add    %al,(%rax)
  4006cf:	00 13                	add    %dl,(%rbx)
  4006d1:	00 00                	add    %al,(%rax)
  4006d3:	00 04 00             	add    %al,(%rax,%rax,1)
	...
  4006f2:	00 00                	add    %al,(%rax)
  4006f4:	02 00                	add    (%rax),%al
	...
  400702:	00 00                	add    %al,(%rax)
  400704:	09 00                	or     %eax,(%rax)
	...
  40070e:	00 00                	add    %al,(%rax)
  400710:	0c 00                	or     $0x0,%al
  400712:	00 00                	add    %al,(%rax)
  400714:	03 00                	add    (%rax),%eax
  400716:	00 00                	add    %al,(%rax)
  400718:	08 00                	or     %al,(%rax)
  40071a:	00 00                	add    %al,(%rax)
  40071c:	0e                   	(bad)  
  40071d:	00 00                	add    %al,(%rax)
  40071f:	00 05 00 00 00 01    	add    %al,0x1000000(%rip)        # 1400725 <_end+0xffdc1d>
  400725:	00 00                	add    %al,(%rax)
  400727:	00 00                	add    %al,(%rax)
  400729:	00 00                	add    %al,(%rax)
  40072b:	00 10                	add    %dl,(%rax)
  40072d:	00 00                	add    %al,(%rax)
  40072f:	00 0b                	add    %cl,(%rbx)
  400731:	00 00                	add    %al,(%rax)
  400733:	00 0f                	add    %cl,(%rdi)
  400735:	00 00                	add    %al,(%rax)
  400737:	00 16                	add    %dl,(%rsi)
  400739:	00 00                	add    %al,(%rax)
  40073b:	00 12                	add    %dl,(%rdx)
  40073d:	00 00                	add    %al,(%rax)
  40073f:	00 0a                	add    %cl,(%rdx)
	...
  400749:	00 00                	add    %al,(%rax)
  40074b:	00 14 00             	add    %dl,(%rax,%rax,1)
	...

Disassembly of section .gnu.version:

0000000000400750 <.gnu.version>:
  400750:	00 00                	add    %al,(%rax)
  400752:	02 00                	add    (%rax),%al
  400754:	02 00                	add    (%rax),%al
  400756:	02 00                	add    (%rax),%al
  400758:	00 00                	add    %al,(%rax)
  40075a:	02 00                	add    (%rax),%al
  40075c:	01 00                	add    %eax,(%rax)
  40075e:	02 00                	add    (%rax),%al
  400760:	02 00                	add    (%rax),%al
  400762:	01 00                	add    %eax,(%rax)
  400764:	02 00                	add    (%rax),%al
  400766:	00 00                	add    %al,(%rax)
  400768:	00 00                	add    %al,(%rax)
  40076a:	00 00                	add    %al,(%rax)
  40076c:	02 00                	add    (%rax),%al
  40076e:	02 00                	add    (%rax),%al
  400770:	02 00                	add    (%rax),%al
  400772:	02 00                	add    (%rax),%al
	...
  400780:	00 00                	add    %al,(%rax)
  400782:	03 00                	add    (%rax),%eax
  400784:	01 00                	add    %eax,(%rax)
  400786:	01 00                	add    %eax,(%rax)
  400788:	01 00                	add    %eax,(%rax)

Disassembly of section .gnu.version_r:

000000000040078c <.gnu.version_r>:
  40078c:	01 00                	add    %eax,(%rax)
  40078e:	02 00                	add    (%rax),%al
  400790:	1f                   	(bad)  
  400791:	00 00                	add    %al,(%rax)
  400793:	00 10                	add    %dl,(%rax)
  400795:	00 00                	add    %al,(%rax)
  400797:	00 00                	add    %al,(%rax)
  400799:	00 00                	add    %al,(%rax)
  40079b:	00 75 1a             	add    %dh,0x1a(%rbp)
  40079e:	69 09 00 00 02 00    	imul   $0x20000,(%rcx),%ecx
  4007a4:	13 00                	adc    (%rax),%eax
  4007a6:	00 00                	add    %al,(%rax)
  4007a8:	10 00                	adc    %al,(%rax)
  4007aa:	00 00                	add    %al,(%rax)
  4007ac:	94                   	xchg   %eax,%esp
  4007ad:	91                   	xchg   %eax,%ecx
  4007ae:	96                   	xchg   %eax,%esi
  4007af:	06                   	(bad)  
  4007b0:	00 00                	add    %al,(%rax)
  4007b2:	03 00                	add    (%rax),%eax
  4007b4:	5c                   	pop    %rsp
  4007b5:	01 00                	add    %eax,(%rax)
  4007b7:	00 00                	add    %al,(%rax)
  4007b9:	00 00                	add    %al,(%rax)
	...

Disassembly of section .rela.dyn:

00000000004007c0 <.rela.dyn>:
  4007c0:	00 27                	add    %ah,(%rdi)
  4007c2:	40 00 00             	add    %al,(%rax)
  4007c5:	00 00                	add    %al,(%rax)
  4007c7:	00 06                	add    %al,(%rsi)
  4007c9:	00 00                	add    %al,(%rax)
  4007cb:	00 04 00             	add    %al,(%rax,%rax,1)
	...

Disassembly of section .rela.plt:

00000000004007d8 <.rela.plt>:
  4007d8:	20 27                	and    %ah,(%rdi)
  4007da:	40 00 00             	add    %al,(%rax)
  4007dd:	00 00                	add    %al,(%rax)
  4007df:	00 07                	add    %al,(%rdi)
  4007e1:	00 00                	add    %al,(%rax)
  4007e3:	00 01                	add    %al,(%rcx)
	...
  4007ed:	00 00                	add    %al,(%rax)
  4007ef:	00 28                	add    %ch,(%rax)
  4007f1:	27                   	(bad)  
  4007f2:	40 00 00             	add    %al,(%rax)
  4007f5:	00 00                	add    %al,(%rax)
  4007f7:	00 07                	add    %al,(%rdi)
  4007f9:	00 00                	add    %al,(%rax)
  4007fb:	00 04 00             	add    %al,(%rax,%rax,1)
	...
  400806:	00 00                	add    %al,(%rax)
  400808:	30 27                	xor    %ah,(%rdi)
  40080a:	40 00 00             	add    %al,(%rax)
  40080d:	00 00                	add    %al,(%rax)
  40080f:	00 07                	add    %al,(%rdi)
  400811:	00 00                	add    %al,(%rax)
  400813:	00 18                	add    %bl,(%rax)
	...
  40081d:	00 00                	add    %al,(%rax)
  40081f:	00 38                	add    %bh,(%rax)
  400821:	27                   	(bad)  
  400822:	40 00 00             	add    %al,(%rax)
  400825:	00 00                	add    %al,(%rax)
  400827:	00 07                	add    %al,(%rdi)
  400829:	00 00                	add    %al,(%rax)
  40082b:	00 13                	add    %dl,(%rbx)
	...
  400835:	00 00                	add    %al,(%rax)
  400837:	00 40 27             	add    %al,0x27(%rax)
  40083a:	40 00 00             	add    %al,(%rax)
  40083d:	00 00                	add    %al,(%rax)
  40083f:	00 07                	add    %al,(%rdi)
  400841:	00 00                	add    %al,(%rax)
  400843:	00 17                	add    %dl,(%rdi)
	...
  40084d:	00 00                	add    %al,(%rax)
  40084f:	00 48 27             	add    %cl,0x27(%rax)
  400852:	40 00 00             	add    %al,(%rax)
  400855:	00 00                	add    %al,(%rax)
  400857:	00 07                	add    %al,(%rdi)
  400859:	00 00                	add    %al,(%rax)
  40085b:	00 15 00 00 00 00    	add    %dl,0x0(%rip)        # 400861 <_init-0x157>
  400861:	00 00                	add    %al,(%rax)
  400863:	00 00                	add    %al,(%rax)
  400865:	00 00                	add    %al,(%rax)
  400867:	00 50 27             	add    %dl,0x27(%rax)
  40086a:	40 00 00             	add    %al,(%rax)
  40086d:	00 00                	add    %al,(%rax)
  40086f:	00 07                	add    %al,(%rdi)
  400871:	00 00                	add    %al,(%rax)
  400873:	00 16                	add    %dl,(%rsi)
	...
  40087d:	00 00                	add    %al,(%rax)
  40087f:	00 58 27             	add    %bl,0x27(%rax)
  400882:	40 00 00             	add    %al,(%rax)
  400885:	00 00                	add    %al,(%rax)
  400887:	00 07                	add    %al,(%rdi)
  400889:	00 00                	add    %al,(%rax)
  40088b:	00 14 00             	add    %dl,(%rax,%rax,1)
	...
  400896:	00 00                	add    %al,(%rax)
  400898:	60                   	(bad)  
  400899:	27                   	(bad)  
  40089a:	40 00 00             	add    %al,(%rax)
  40089d:	00 00                	add    %al,(%rax)
  40089f:	00 07                	add    %al,(%rdi)
  4008a1:	00 00                	add    %al,(%rax)
  4008a3:	00 12                	add    %dl,(%rdx)
	...
  4008ad:	00 00                	add    %al,(%rax)
  4008af:	00 68 27             	add    %ch,0x27(%rax)
  4008b2:	40 00 00             	add    %al,(%rax)
  4008b5:	00 00                	add    %al,(%rax)
  4008b7:	00 07                	add    %al,(%rdi)
  4008b9:	00 00                	add    %al,(%rax)
  4008bb:	00 05 00 00 00 00    	add    %al,0x0(%rip)        # 4008c1 <_init-0xf7>
  4008c1:	00 00                	add    %al,(%rax)
  4008c3:	00 00                	add    %al,(%rax)
  4008c5:	00 00                	add    %al,(%rax)
  4008c7:	00 70 27             	add    %dh,0x27(%rax)
  4008ca:	40 00 00             	add    %al,(%rax)
  4008cd:	00 00                	add    %al,(%rax)
  4008cf:	00 07                	add    %al,(%rdi)
  4008d1:	00 00                	add    %al,(%rax)
  4008d3:	00 19                	add    %bl,(%rcx)
	...
  4008dd:	00 00                	add    %al,(%rax)
  4008df:	00 78 27             	add    %bh,0x27(%rax)
  4008e2:	40 00 00             	add    %al,(%rax)
  4008e5:	00 00                	add    %al,(%rax)
  4008e7:	00 07                	add    %al,(%rdi)
  4008e9:	00 00                	add    %al,(%rax)
  4008eb:	00 07                	add    %al,(%rdi)
	...
  4008f5:	00 00                	add    %al,(%rax)
  4008f7:	00 80 27 40 00 00    	add    %al,0x4027(%rax)
  4008fd:	00 00                	add    %al,(%rax)
  4008ff:	00 07                	add    %al,(%rdi)
  400901:	00 00                	add    %al,(%rax)
  400903:	00 10                	add    %dl,(%rax)
	...
  40090d:	00 00                	add    %al,(%rax)
  40090f:	00 88 27 40 00 00    	add    %cl,0x4027(%rax)
  400915:	00 00                	add    %al,(%rax)
  400917:	00 07                	add    %al,(%rdi)
  400919:	00 00                	add    %al,(%rax)
  40091b:	00 0e                	add    %cl,(%rsi)
	...
  400925:	00 00                	add    %al,(%rax)
  400927:	00 90 27 40 00 00    	add    %dl,0x4027(%rax)
  40092d:	00 00                	add    %al,(%rax)
  40092f:	00 07                	add    %al,(%rdi)
  400931:	00 00                	add    %al,(%rax)
  400933:	00 0a                	add    %cl,(%rdx)
	...
  40093d:	00 00                	add    %al,(%rax)
  40093f:	00 98 27 40 00 00    	add    %bl,0x4027(%rax)
  400945:	00 00                	add    %al,(%rax)
  400947:	00 07                	add    %al,(%rdi)
  400949:	00 00                	add    %al,(%rax)
  40094b:	00 0f                	add    %cl,(%rdi)
	...
  400955:	00 00                	add    %al,(%rax)
  400957:	00 a0 27 40 00 00    	add    %ah,0x4027(%rax)
  40095d:	00 00                	add    %al,(%rax)
  40095f:	00 07                	add    %al,(%rdi)
  400961:	00 00                	add    %al,(%rax)
  400963:	00 08                	add    %cl,(%rax)
	...
  40096d:	00 00                	add    %al,(%rax)
  40096f:	00 a8 27 40 00 00    	add    %ch,0x4027(%rax)
  400975:	00 00                	add    %al,(%rax)
  400977:	00 07                	add    %al,(%rdi)
  400979:	00 00                	add    %al,(%rax)
  40097b:	00 02                	add    %al,(%rdx)
	...
  400985:	00 00                	add    %al,(%rax)
  400987:	00 b0 27 40 00 00    	add    %dh,0x4027(%rax)
  40098d:	00 00                	add    %al,(%rax)
  40098f:	00 07                	add    %al,(%rdi)
  400991:	00 00                	add    %al,(%rax)
  400993:	00 11                	add    %dl,(%rcx)
	...
  40099d:	00 00                	add    %al,(%rax)
  40099f:	00 b8 27 40 00 00    	add    %bh,0x4027(%rax)
  4009a5:	00 00                	add    %al,(%rax)
  4009a7:	00 07                	add    %al,(%rdi)
  4009a9:	00 00                	add    %al,(%rax)
  4009ab:	00 03                	add    %al,(%rbx)
	...

Disassembly of section .init:

00000000004009b8 <_init>:
  4009b8:	48 83 ec 08          	sub    $0x8,%rsp
  4009bc:	48 8b 05 3d 1d 00 00 	mov    0x1d3d(%rip),%rax        # 402700 <_fini+0x14cc>
  4009c3:	48 85 c0             	test   %rax,%rax
  4009c6:	74 05                	je     4009cd <_init+0x15>
  4009c8:	e8 33 00 00 00       	callq  400a00 <__gmon_start__@plt>
  4009cd:	48 83 c4 08          	add    $0x8,%rsp
  4009d1:	c3                   	retq   

Disassembly of section .plt:

00000000004009e0 <__libc_start_main@plt-0x10>:
  4009e0:	ff 35 2a 1d 00 00    	pushq  0x1d2a(%rip)        # 402710 <_fini+0x14dc>
  4009e6:	ff 25 2c 1d 00 00    	jmpq   *0x1d2c(%rip)        # 402718 <_fini+0x14e4>
  4009ec:	90                   	nop
  4009ed:	90                   	nop
  4009ee:	90                   	nop
  4009ef:	90                   	nop

00000000004009f0 <__libc_start_main@plt>:
  4009f0:	ff 25 2a 1d 00 00    	jmpq   *0x1d2a(%rip)        # 402720 <_fini+0x14ec>
  4009f6:	68 00 00 00 00       	pushq  $0x0
  4009fb:	e9 e0 ff ff ff       	jmpq   4009e0 <_init+0x28>

0000000000400a00 <__gmon_start__@plt>:
  400a00:	ff 25 22 1d 00 00    	jmpq   *0x1d22(%rip)        # 402728 <_fini+0x14f4>
  400a06:	68 01 00 00 00       	pushq  $0x1
  400a0b:	e9 d0 ff ff ff       	jmpq   4009e0 <_init+0x28>

0000000000400a10 <SHA1@plt>:
  400a10:	ff 25 1a 1d 00 00    	jmpq   *0x1d1a(%rip)        # 402730 <_fini+0x14fc>
  400a16:	68 02 00 00 00       	pushq  $0x2
  400a1b:	e9 c0 ff ff ff       	jmpq   4009e0 <_init+0x28>

0000000000400a20 <EVP_CIPHER_CTX_init@plt>:
  400a20:	ff 25 12 1d 00 00    	jmpq   *0x1d12(%rip)        # 402738 <_fini+0x1504>
  400a26:	68 03 00 00 00       	pushq  $0x3
  400a2b:	e9 b0 ff ff ff       	jmpq   4009e0 <_init+0x28>

0000000000400a30 <EVP_aes_128_ofb@plt>:
  400a30:	ff 25 0a 1d 00 00    	jmpq   *0x1d0a(%rip)        # 402740 <_fini+0x150c>
  400a36:	68 04 00 00 00       	pushq  $0x4
  400a3b:	e9 a0 ff ff ff       	jmpq   4009e0 <_init+0x28>

0000000000400a40 <EVP_DecryptInit_ex@plt>:
  400a40:	ff 25 02 1d 00 00    	jmpq   *0x1d02(%rip)        # 402748 <_fini+0x1514>
  400a46:	68 05 00 00 00       	pushq  $0x5
  400a4b:	e9 90 ff ff ff       	jmpq   4009e0 <_init+0x28>

0000000000400a50 <EVP_DecryptUpdate@plt>:
  400a50:	ff 25 fa 1c 00 00    	jmpq   *0x1cfa(%rip)        # 402750 <_fini+0x151c>
  400a56:	68 06 00 00 00       	pushq  $0x6
  400a5b:	e9 80 ff ff ff       	jmpq   4009e0 <_init+0x28>

0000000000400a60 <EVP_DecryptFinal_ex@plt>:
  400a60:	ff 25 f2 1c 00 00    	jmpq   *0x1cf2(%rip)        # 402758 <_fini+0x1524>
  400a66:	68 07 00 00 00       	pushq  $0x7
  400a6b:	e9 70 ff ff ff       	jmpq   4009e0 <_init+0x28>

0000000000400a70 <EVP_CIPHER_CTX_cleanup@plt>:
  400a70:	ff 25 ea 1c 00 00    	jmpq   *0x1cea(%rip)        # 402760 <_fini+0x152c>
  400a76:	68 08 00 00 00       	pushq  $0x8
  400a7b:	e9 60 ff ff ff       	jmpq   4009e0 <_init+0x28>

0000000000400a80 <ptrace@plt>:
  400a80:	ff 25 e2 1c 00 00    	jmpq   *0x1ce2(%rip)        # 402768 <_fini+0x1534>
  400a86:	68 09 00 00 00       	pushq  $0x9
  400a8b:	e9 50 ff ff ff       	jmpq   4009e0 <_init+0x28>

0000000000400a90 <memcpy@plt>:
  400a90:	ff 25 da 1c 00 00    	jmpq   *0x1cda(%rip)        # 402770 <_fini+0x153c>
  400a96:	68 0a 00 00 00       	pushq  $0xa
  400a9b:	e9 40 ff ff ff       	jmpq   4009e0 <_init+0x28>

0000000000400aa0 <printf@plt>:
  400aa0:	ff 25 d2 1c 00 00    	jmpq   *0x1cd2(%rip)        # 402778 <_fini+0x1544>
  400aa6:	68 0b 00 00 00       	pushq  $0xb
  400aab:	e9 30 ff ff ff       	jmpq   4009e0 <_init+0x28>

0000000000400ab0 <exit@plt>:
  400ab0:	ff 25 ca 1c 00 00    	jmpq   *0x1cca(%rip)        # 402780 <_fini+0x154c>
  400ab6:	68 0c 00 00 00       	pushq  $0xc
  400abb:	e9 20 ff ff ff       	jmpq   4009e0 <_init+0x28>

0000000000400ac0 <alarm@plt>:
  400ac0:	ff 25 c2 1c 00 00    	jmpq   *0x1cc2(%rip)        # 402788 <_fini+0x1554>
  400ac6:	68 0d 00 00 00       	pushq  $0xd
  400acb:	e9 10 ff ff ff       	jmpq   4009e0 <_init+0x28>

0000000000400ad0 <signal@plt>:
  400ad0:	ff 25 ba 1c 00 00    	jmpq   *0x1cba(%rip)        # 402790 <_fini+0x155c>
  400ad6:	68 0e 00 00 00       	pushq  $0xe
  400adb:	e9 00 ff ff ff       	jmpq   4009e0 <_init+0x28>

0000000000400ae0 <gettimeofday@plt>:
  400ae0:	ff 25 b2 1c 00 00    	jmpq   *0x1cb2(%rip)        # 402798 <_fini+0x1564>
  400ae6:	68 0f 00 00 00       	pushq  $0xf
  400aeb:	e9 f0 fe ff ff       	jmpq   4009e0 <_init+0x28>

0000000000400af0 <sysconf@plt>:
  400af0:	ff 25 aa 1c 00 00    	jmpq   *0x1caa(%rip)        # 4027a0 <_fini+0x156c>
  400af6:	68 10 00 00 00       	pushq  $0x10
  400afb:	e9 e0 fe ff ff       	jmpq   4009e0 <_init+0x28>

0000000000400b00 <perror@plt>:
  400b00:	ff 25 a2 1c 00 00    	jmpq   *0x1ca2(%rip)        # 4027a8 <_fini+0x1574>
  400b06:	68 11 00 00 00       	pushq  $0x11
  400b0b:	e9 d0 fe ff ff       	jmpq   4009e0 <_init+0x28>

0000000000400b10 <memalign@plt>:
  400b10:	ff 25 9a 1c 00 00    	jmpq   *0x1c9a(%rip)        # 4027b0 <_fini+0x157c>
  400b16:	68 12 00 00 00       	pushq  $0x12
  400b1b:	e9 c0 fe ff ff       	jmpq   4009e0 <_init+0x28>

0000000000400b20 <mprotect@plt>:
  400b20:	ff 25 92 1c 00 00    	jmpq   *0x1c92(%rip)        # 4027b8 <_fini+0x1584>
  400b26:	68 13 00 00 00       	pushq  $0x13
  400b2b:	e9 b0 fe ff ff       	jmpq   4009e0 <_init+0x28>

Disassembly of section .text:

# begin _start()

0000000000400b30 <.text>:
  400b30:	31 ed                	xor    %ebp,%ebp
  400b32:	49 89 d1             	mov    %rdx,%r9
  400b35:	5e                   	pop    %rsi
  400b36:	48 89 e2             	mov    %rsp,%rdx
  400b39:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  400b3d:	50                   	push   %rax
  400b3e:	54                   	push   %rsp
  400b3f:	49 c7 c0 30 12 40 00 	mov    $0x401230,%r8
  400b46:	48 c7 c1 c0 11 40 00 	mov    $0x4011c0,%rcx
  400b4d:	48 c7 c7 d0 10 40 00 	mov    $0x4010d0,%rdi
  400b54:	e8 97 fe ff ff       	callq  4009f0 <__libc_start_main@plt>
  400b59:	f4                   	hlt    

# end _start()

  400b5a:	66 90                	xchg   %ax,%ax
  400b5c:	0f 1f 40 00          	nopl   0x0(%rax)
  400b60:	b8 e7 2a 40 00       	mov    $0x402ae7,%eax
  400b65:	55                   	push   %rbp
  400b66:	48 2d e0 2a 40 00    	sub    $0x402ae0,%rax
  400b6c:	48 83 f8 0e          	cmp    $0xe,%rax
  400b70:	48 89 e5             	mov    %rsp,%rbp
  400b73:	77 02                	ja     400b77 <mprotect@plt+0x57>
  400b75:	5d                   	pop    %rbp
  400b76:	c3                   	retq   
  400b77:	b8 00 00 00 00       	mov    $0x0,%eax
  400b7c:	48 85 c0             	test   %rax,%rax
  400b7f:	74 f4                	je     400b75 <mprotect@plt+0x55>
  400b81:	5d                   	pop    %rbp
  400b82:	bf e0 2a 40 00       	mov    $0x402ae0,%edi
  400b87:	ff e0                	jmpq   *%rax
  400b89:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  400b90:	b8 e0 2a 40 00       	mov    $0x402ae0,%eax
  400b95:	55                   	push   %rbp
  400b96:	48 2d e0 2a 40 00    	sub    $0x402ae0,%rax
  400b9c:	48 c1 f8 03          	sar    $0x3,%rax
  400ba0:	48 89 e5             	mov    %rsp,%rbp
  400ba3:	48 89 c2             	mov    %rax,%rdx
  400ba6:	48 c1 ea 3f          	shr    $0x3f,%rdx
  400baa:	48 01 d0             	add    %rdx,%rax
  400bad:	48 d1 f8             	sar    %rax
  400bb0:	75 02                	jne    400bb4 <mprotect@plt+0x94>
  400bb2:	5d                   	pop    %rbp
  400bb3:	c3                   	retq   
  400bb4:	ba 00 00 00 00       	mov    $0x0,%edx
  400bb9:	48 85 d2             	test   %rdx,%rdx
  400bbc:	74 f4                	je     400bb2 <mprotect@plt+0x92>
  400bbe:	5d                   	pop    %rbp
  400bbf:	48 89 c6             	mov    %rax,%rsi
  400bc2:	bf e0 2a 40 00       	mov    $0x402ae0,%edi
  400bc7:	ff e2                	jmpq   *%rdx
  400bc9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  400bd0:	80 3d 21 1f 00 00 00 	cmpb   $0x0,0x1f21(%rip)        # 402af8 <__bss_start>
  400bd7:	75 11                	jne    400bea <mprotect@plt+0xca>
  400bd9:	55                   	push   %rbp
  400bda:	48 89 e5             	mov    %rsp,%rbp
  400bdd:	e8 7e ff ff ff       	callq  400b60 <mprotect@plt+0x40>
  400be2:	5d                   	pop    %rbp
  400be3:	c6 05 0e 1f 00 00 01 	movb   $0x1,0x1f0e(%rip)        # 402af8 <__bss_start>
  400bea:	f3 c3                	repz retq 
  400bec:	0f 1f 40 00          	nopl   0x0(%rax)

# begin f0()

  400bf0:	48 83 3d e0 1e 00 00 	cmpq   $0x0,0x1ee0(%rip)        # 402ad8 <_fini+0x18a4>
  400bf7:	00 
  400bf8:	74 1e                	je     400c18 <mprotect@plt+0xf8>   # goto 0x400c18
  400bfa:	b8 00 00 00 00       	mov    $0x0,%eax
  400bff:	48 85 c0             	test   %rax,%rax
  400c02:	74 14                	je     400c18 <mprotect@plt+0xf8>
  400c04:	55                   	push   %rbp
  400c05:	bf d8 2a 40 00       	mov    $0x402ad8,%edi
  400c0a:	48 89 e5             	mov    %rsp,%rbp
  400c0d:	ff d0                	callq  *%rax
  400c0f:	5d                   	pop    %rbp
  400c10:	e9 7b ff ff ff       	jmpq   400b90 <mprotect@plt+0x70>
  400c15:	0f 1f 00             	nopl   (%rax)

  400c18:	e9 73 ff ff ff       	jmpq   400b90 <mprotect@plt+0x70>
  400c1d:	0f 1f 00             	nopl   (%rax)
  400c20:	89 7c 24 fc          	mov    %edi,-0x4(%rsp)
  400c24:	c3                   	retq   
  400c25:	66 66 2e 0f 1f 84 00 	data32 nopw %cs:0x0(%rax,%rax,1)
  400c2c:	00 00 00 00 

# begin sha1_and_evp()

  400c30:	55                   	push   %rbp
  400c31:	48 89 e5             	mov    %rsp,%rbp
  400c34:	48 81 ec 50 01 00 00 	sub    $0x150,%rsp
  400c3b:	48 8d 55 d0          	lea    -0x30(%rbp),%rdx
  400c3f:	48 8d 04 25 d0 27 40 	lea    0x4027d0,%rax
  400c46:	00 
  400c47:	48 8d 0c 25 00 28 40 	lea    0x402800,%rcx
  400c4e:	00 
  400c4f:	48 89 4d f8          	mov    %rcx,-0x8(%rbp)
  400c53:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  400c57:	48 c7 45 e8 04 00 00 	movq   $0x4,-0x18(%rbp)
  400c5e:	00 
  400c5f:	48 8b 7d f0          	mov    -0x10(%rbp),%rdi
  400c63:	48 8b 75 e8          	mov    -0x18(%rbp),%rsi
  400c67:	e8 a4 fd ff ff       	callq  400a10 <SHA1@plt>        # call SHA1(%rdi, %rsi, %rdx); SHA1(0x4027d0, 4, 0x402800); result is in sha = -0x30(%rbp)
  400c6c:	48 8b 0c 25 50 12 40 	mov    0x401250,%rcx
  400c73:	00 
  400c74:	48 89 4d b0          	mov    %rcx,-0x50(%rbp)
  400c78:	48 8b 0c 25 58 12 40 	mov    0x401258,%rcx
  400c7f:	00 
  400c80:	48 89 4d b8          	mov    %rcx,-0x48(%rbp)
  400c84:	44 8a 04 25 60 12 40 	mov    0x401260,%r8b
  400c8b:	00 
  400c8c:	44 88 45 c0          	mov    %r8b,-0x40(%rbp)
  400c90:	48 8d 8d f0 fe ff ff 	lea    -0x110(%rbp),%rcx
  400c97:	48 8d 55 b0          	lea    -0x50(%rbp),%rdx
  400c9b:	48 89 55 a8          	mov    %rdx,-0x58(%rbp)
  400c9f:	c7 45 a4 a0 00 00 00 	movl   $0xa0,-0x5c(%rbp)
  400ca6:	44 8b 4d a4          	mov    -0x5c(%rbp),%r9d
  400caa:	44 89 4d a0          	mov    %r9d,-0x60(%rbp)
  400cae:	c7 45 9c 00 00 00 00 	movl   $0x0,-0x64(%rbp)
  400cb5:	48 89 8d e8 fe ff ff 	mov    %rcx,-0x118(%rbp)
  400cbc:	48 8b bd e8 fe ff ff 	mov    -0x118(%rbp),%rdi
  400cc3:	48 89 85 e0 fe ff ff 	mov    %rax,-0x120(%rbp)
  400cca:	e8 51 fd ff ff       	callq  400a20 <EVP_CIPHER_CTX_init@plt>
  400ccf:	48 8b bd e8 fe ff ff 	mov    -0x118(%rbp),%rdi
  400cd6:	48 89 bd d8 fe ff ff 	mov    %rdi,-0x128(%rbp)
  400cdd:	e8 4e fd ff ff       	callq  400a30 <EVP_aes_128_ofb@plt>
  400ce2:	48 ba 00 00 00 00 00 	movabs $0x0,%rdx
  400ce9:	00 00 00 
  400cec:	48 8d 4d d0          	lea    -0x30(%rbp),%rcx         # sha buffer!
  400cf0:	4c 8b 45 a8          	mov    -0x58(%rbp),%r8
  400cf4:	48 8b bd d8 fe ff ff 	mov    -0x128(%rbp),%rdi
  400cfb:	48 89 c6             	mov    %rax,%rsi
  400cfe:	e8 3d fd ff ff       	callq  400a40 <EVP_DecryptInit_ex@plt> # f(%rdi, %rsi, %rdx, %rcx, %r8); sha is used as the key.
  400d03:	48 b9 00 00 00 00 00 	movabs $0x0,%rcx
  400d0a:	00 00 00 
  400d0d:	48 8b bd e8 fe ff ff 	mov    -0x118(%rbp),%rdi
  400d14:	48 89 ce             	mov    %rcx,%rsi
  400d17:	48 89 ca             	mov    %rcx,%rdx
  400d1a:	48 89 8d d0 fe ff ff 	mov    %rcx,-0x130(%rbp)
  400d21:	4c 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%r8
  400d28:	89 85 cc fe ff ff    	mov    %eax,-0x134(%rbp)
  400d2e:	e8 0d fd ff ff       	callq  400a40 <EVP_DecryptInit_ex@plt>
  400d33:	48 8d 55 a0          	lea    -0x60(%rbp),%rdx
  400d37:	48 8b bd e8 fe ff ff 	mov    -0x118(%rbp),%rdi
  400d3e:	48 8b 34 25 00 2b 40 	mov    0x402b00,%rsi
  400d45:	00 
  400d46:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
  400d4a:	44 8b 45 a4          	mov    -0x5c(%rbp),%r8d
  400d4e:	89 85 c8 fe ff ff    	mov    %eax,-0x138(%rbp)
  400d54:	e8 f7 fc ff ff       	callq  400a50 <EVP_DecryptUpdate@plt>   # f(%rdi, %rsi, %rdx, %rcx, %r8); decrypts "This is not the secret you're looking for" + some additional data at the end.
  400d59:	48 8d 55 9c          	lea    -0x64(%rbp),%rdx
  400d5d:	48 8b bd e8 fe ff ff 	mov    -0x118(%rbp),%rdi
  400d64:	48 8b 0c 25 00 2b 40 	mov    0x402b00,%rcx
  400d6b:	00 
  400d6c:	48 63 75 a0          	movslq -0x60(%rbp),%rsi
  400d70:	48 01 f1             	add    %rsi,%rcx
  400d73:	48 89 ce             	mov    %rcx,%rsi
  400d76:	89 85 c4 fe ff ff    	mov    %eax,-0x13c(%rbp)
  400d7c:	e8 df fc ff ff       	callq  400a60 <EVP_DecryptFinal_ex@plt> # f(%rdi, %rsi, %rdx)
  400d81:	44 8b 45 a0          	mov    -0x60(%rbp),%r8d
  400d85:	44 03 45 9c          	add    -0x64(%rbp),%r8d
  400d89:	44 89 45 a4          	mov    %r8d,-0x5c(%rbp)
  400d8d:	48 8b bd e8 fe ff ff 	mov    -0x118(%rbp),%rdi
  400d94:	89 85 c0 fe ff ff    	mov    %eax,-0x140(%rbp)
  400d9a:	e8 d1 fc ff ff       	callq  400a70 <EVP_CIPHER_CTX_cleanup@plt>
  400d9f:	89 85 bc fe ff ff    	mov    %eax,-0x144(%rbp)
  400da5:	48 81 c4 50 01 00 00 	add    $0x150,%rsp
  400dac:	5d                   	pop    %rbp
  400dad:	c3                   	retq   

# end sha1_and_evp()

  400dae:	66 90                	xchg   %ax,%ax
  400db0:	89 7c 24 fc          	mov    %edi,-0x4(%rsp)
  400db4:	c3                   	retq   
  400db5:	66 66 2e 0f 1f 84 00 	data32 nopw %cs:0x0(%rax,%rax,1)
  400dbc:	00 00 00 00 

# begin check_for_ptrace()

  400dc0:	55                   	push   %rbp
  400dc1:	48 89 e5             	mov    %rsp,%rbp
  400dc4:	48 83 ec 40          	sub    $0x40,%rsp
  400dc8:	b8 00 00 00 00       	mov    $0x0,%eax
  400dcd:	ba 01 00 00 00       	mov    $0x1,%edx
  400dd2:	89 c7                	mov    %eax,%edi
  400dd4:	89 c6                	mov    %eax,%esi
  400dd6:	89 c1                	mov    %eax,%ecx
  400dd8:	b0 00                	mov    $0x0,%al
  400dda:	e8 a1 fc ff ff       	callq  400a80 <ptrace@plt>
  400ddf:	48 3d 00 00 00 00    	cmp    $0x0,%rax
  400de5:	90                   	nop
  400de6:	e9 7b 00 00 00       	jmpq   400e66 <mprotect@plt+0x346>  # originally: if ptrace() >= 0, jump to return_from_f
  400deb:	48 8d 34 25 70 12 40 	lea    0x401270,%rsi
  400df2:	00 
  400df3:	48 ba 27 00 00 00 00 	movabs $0x27,%rdx
  400dfa:	00 00 00 
  400dfd:	48 8d 45 d0          	lea    -0x30(%rbp),%rax
  400e01:	48 89 c7             	mov    %rax,%rdi
  400e04:	e8 87 fc ff ff       	callq  400a90 <memcpy@plt>
  400e09:	c7 45 cc 00 00 00 00 	movl   $0x0,-0x34(%rbp)
  400e10:	81 7d cc 26 00 00 00 	cmpl   $0x26,-0x34(%rbp)
  400e17:	0f 8d 29 00 00 00    	jge    400e46 <mprotect@plt+0x326>
  400e1d:	48 63 45 cc          	movslq -0x34(%rbp),%rax
  400e21:	0f be 4c 05 d0       	movsbl -0x30(%rbp,%rax,1),%ecx
  400e26:	81 f1 ab 00 00 00    	xor    $0xab,%ecx
  400e2c:	88 ca                	mov    %cl,%dl
  400e2e:	48 63 45 cc          	movslq -0x34(%rbp),%rax
  400e32:	88 54 05 d0          	mov    %dl,-0x30(%rbp,%rax,1)
  400e36:	8b 45 cc             	mov    -0x34(%rbp),%eax
  400e39:	05 01 00 00 00       	add    $0x1,%eax
  400e3e:	89 45 cc             	mov    %eax,-0x34(%rbp)
  400e41:	e9 ca ff ff ff       	jmpq   400e10 <mprotect@plt+0x2f0>
  400e46:	48 8d 3c 25 c7 12 40 	lea    0x4012c7,%rdi
  400e4d:	00 
  400e4e:	48 8d 75 d0          	lea    -0x30(%rbp),%rsi
  400e52:	b0 00                	mov    $0x0,%al
  400e54:	e8 47 fc ff ff       	callq  400aa0 <printf@plt>
  400e59:	bf 01 00 00 00       	mov    $0x1,%edi
  400e5e:	89 45 c8             	mov    %eax,-0x38(%rbp)
  400e61:	e8 4a fc ff ff       	callq  400ab0 <exit@plt>

# return_from_f:

  400e66:	48 83 c4 40          	add    $0x40,%rsp
  400e6a:	5d                   	pop    %rbp
  400e6b:	c3                   	retq   

# end check_for_ptrace()

  400e6c:	0f 1f 40 00          	nopl   0x0(%rax)

# begin f1()

  400e70:	55                   	push   %rbp
  400e71:	48 89 e5             	mov    %rsp,%rbp
  400e74:	48 83 ec 30          	sub    $0x30,%rsp
  400e78:	bf 01 00 00 00       	mov    $0x1,%edi
  400e7d:	e8 3e fc ff ff       	callq  400ac0 <alarm@plt>
  400e82:	bf 0e 00 00 00       	mov    $0xe,%edi
  400e87:	48 8d 34 25 b0 0d 40 	lea    0x400db0,%rsi
  400e8e:	00 
  400e8f:	89 45 e8             	mov    %eax,-0x18(%rbp)
  400e92:	e8 39 fc ff ff       	callq  400ad0 <signal@plt>
  400e97:	48 8d 7d f0          	lea    -0x10(%rbp),%rdi             # -0x10(%rbp) = time
  400e9b:	48 be 00 00 00 00 00 	movabs $0x0,%rsi
  400ea2:	00 00 00 
  400ea5:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
  400ea9:	e8 32 fc ff ff       	callq  400ae0 <gettimeofday@plt>    # gettimeofday(%rdi, NULL); 
  400eae:	bf 1e 00 00 00       	mov    $0x1e,%edi                   # %rdi = 0x1e
  400eb3:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi             # %rsi = time
  400eb7:	48 b9 00 00 ff ff 00 	movabs $0xffff0000,%rcx             # %rcx = 0xffff0000
  400ebe:	00 00 00 
  400ec1:	48 21 ce             	and    %rcx,%rsi                    # %rsi &= 0xffff0000
  400ec4:	48 81 ce de c0 00 00 	or     $0xc0de,%rsi                 # %rsi |= 0x0000c0de
  400ecb:	48 89 34 25 d0 27 40 	mov    %rsi,0x4027d0                # 0x4027d0 = 0x????c0de;
  400ed2:	00 
  400ed3:	89 45 dc             	mov    %eax,-0x24(%rbp)
  400ed6:	e8 15 fc ff ff       	callq  400af0 <sysconf@plt>
  400edb:	89 c7                	mov    %eax,%edi
  400edd:	89 7d ec             	mov    %edi,-0x14(%rbp)
  400ee0:	81 7d ec ff ff ff ff 	cmpl   $0xffffffff,-0x14(%rbp)      # if (ret == -1) {
  400ee7:	0f 85 1c 00 00 00    	jne    400f09 <mprotect@plt+0x3e9>
  400eed:	e9 00 00 00 00       	jmpq   400ef2 <mprotect@plt+0x3d2>
  400ef2:	48 8d 3c 25 cb 12 40 	lea    0x4012cb,%rdi
  400ef9:	00 
  400efa:	e8 01 fc ff ff       	callq  400b00 <perror@plt>          # perror()
  400eff:	bf 01 00 00 00       	mov    $0x1,%edi
  400f04:	e8 a7 fb ff ff       	callq  400ab0 <exit@plt>            # exit() } // end if
  400f09:	48 63 7d ec          	movslq -0x14(%rbp),%rdi
  400f0d:	8b 45 ec             	mov    -0x14(%rbp),%eax
  400f10:	c1 e0 02             	shl    $0x2,%eax
  400f13:	48 63 f0             	movslq %eax,%rsi
  400f16:	e8 f5 fb ff ff       	callq  400b10 <memalign@plt>        # *0x402b00 = memalign(%rdi, %rsi); (0x404000 in my tests)
  400f1b:	48 89 04 25 00 2b 40 	mov    %rax,0x402b00
  400f22:	00 
  400f23:	48 81 3c 25 00 2b 40 	cmpq   $0x0,0x402b00                # if *0x402b00 == 0 {
  400f2a:	00 00 00 00 00 
  400f2f:	0f 85 1c 00 00 00    	jne    400f51 <mprotect@plt+0x431>
  400f35:	e9 00 00 00 00       	jmpq   400f3a <mprotect@plt+0x41a>
  400f3a:	48 8d 3c 25 d3 12 40 	lea    0x4012d3,%rdi
  400f41:	00 
  400f42:	e8 b9 fb ff ff       	callq  400b00 <perror@plt>          # perror()
  400f47:	bf 01 00 00 00       	mov    $0x1,%edi
  400f4c:	e8 5f fb ff ff       	callq  400ab0 <exit@plt>            # exit() } // end if
  400f51:	ba 07 00 00 00       	mov    $0x7,%edx              
  400f56:	48 8b 3c 25 00 2b 40 	mov    0x402b00,%rdi
  400f5d:	00 
  400f5e:	8b 45 ec             	mov    -0x14(%rbp),%eax
  400f61:	c1 e0 02             	shl    $0x2,%eax
  400f64:	48 63 f0             	movslq %eax,%rsi
  400f67:	e8 b4 fb ff ff       	callq  400b20 <mprotect@plt>
  400f6c:	3d ff ff ff ff       	cmp    $0xffffffff,%eax             # if mprotect == -1 {
  400f71:	0f 85 1c 00 00 00    	jne    400f93 <mprotect@plt+0x473>
  400f77:	e9 00 00 00 00       	jmpq   400f7c <mprotect@plt+0x45c>
  400f7c:	48 8d 3c 25 dc 12 40 	lea    0x4012dc,%rdi
  400f83:	00 
  400f84:	e8 77 fb ff ff       	callq  400b00 <perror@plt>          # perror()
  400f89:	bf 01 00 00 00       	mov    $0x1,%edi
  400f8e:	e8 1d fb ff ff       	callq  400ab0 <exit@plt>            # exit() } // end if
  400f93:	e8 28 fe ff ff       	callq  400dc0 <mprotect@plt+0x2a0>  # check_for_ptrace()
  400f98:	48 83 c4 30          	add    $0x30,%rsp
  400f9c:	5d                   	pop    %rbp
  400f9d:	c3                   	retq   

# end f1()

  400f9e:	66 90                	xchg   %ax,%ax

# begin do_weird_calcs()

  400fa0:	0f b6 05 2a 18 00 00 	movzbl 0x182a(%rip),%eax        # 4027d1 <_fini+0x159d>
  400fa7:	0f b6 0d 24 18 00 00 	movzbl 0x1824(%rip),%ecx        # 4027d2 <_fini+0x159e>
  400fae:	0f af c8             	imul   %eax,%ecx
  400fb1:	0f b6 05 1b 18 00 00 	movzbl 0x181b(%rip),%eax        # 4027d3 <_fini+0x159f>
  400fb8:	01 c1                	add    %eax,%ecx
  400fba:	c1 f9 1f             	sar    $0x1f,%ecx
  400fbd:	c1 e9 18             	shr    $0x18,%ecx
  400fc0:	88 ca                	mov    %cl,%dl
  400fc2:	88 54 24 ff          	mov    %dl,-0x1(%rsp)
  400fc6:	0f b6 05 04 18 00 00 	movzbl 0x1804(%rip),%eax        # 4027d1 <_fini+0x159d>
  400fcd:	0f b6 0d fe 17 00 00 	movzbl 0x17fe(%rip),%ecx        # 4027d2 <_fini+0x159e>
  400fd4:	0f af c8             	imul   %eax,%ecx
  400fd7:	0f be 44 24 ff       	movsbl -0x1(%rsp),%eax
  400fdc:	89 c6                	mov    %eax,%esi
  400fde:	01 ce                	add    %ecx,%esi
  400fe0:	0f b6 0d ec 17 00 00 	movzbl 0x17ec(%rip),%ecx        # 4027d3 <_fini+0x159f>
  400fe7:	01 ce                	add    %ecx,%esi
  400fe9:	29 c6                	sub    %eax,%esi
  400feb:	40 88 f2             	mov    %sil,%dl
  400fee:	0f be c2             	movsbl %dl,%eax
  400ff1:	89 c1                	mov    %eax,%ecx
  400ff3:	c1 f9 1f             	sar    $0x1f,%ecx
  400ff6:	c1 e9 18             	shr    $0x18,%ecx
  400ff9:	89 c6                	mov    %eax,%esi
  400ffb:	01 ce                	add    %ecx,%esi
  400ffd:	81 e6 00 ff ff ff    	and    $0xffffff00,%esi
  401003:	29 f0                	sub    %esi,%eax
  401005:	88 c2                	mov    %al,%dl
  401007:	88 54 24 fe          	mov    %dl,-0x2(%rsp)
  40100b:	0f b6 04 25 d3 27 40 	movzbl 0x4027d3,%eax
  401012:	00 
  401013:	0f b6 0c 25 d2 27 40 	movzbl 0x4027d2,%ecx
  40101a:	00 
  40101b:	0f b6 34 25 d1 27 40 	movzbl 0x4027d1,%esi
  401022:	00 
  401023:	01 f1                	add    %esi,%ecx
  401025:	31 c8                	xor    %ecx,%eax
  401027:	0f b6 0c 25 d0 27 40 	movzbl 0x4027d0,%ecx
  40102e:	00 
  40102f:	31 c8                	xor    %ecx,%eax
  401031:	88 c2                	mov    %al,%dl
  401033:	88 54 24 fd          	mov    %dl,-0x3(%rsp)
  401037:	0f be 44 24 fe       	movsbl -0x2(%rsp),%eax
  40103c:	3d 2f 00 00 00       	cmp    $0x2f,%eax
  401041:	0f 94 c2             	sete   %dl
  401044:	80 e2 01             	and    $0x1,%dl
  401047:	0f b6 c2             	movzbl %dl,%eax
  40104a:	0f be 4c 24 fd       	movsbl -0x3(%rsp),%ecx
  40104f:	81 f9 5b 00 00 00    	cmp    $0x5b,%ecx
  401055:	0f 94 c2             	sete   %dl
  401058:	80 e2 01             	and    $0x1,%dl
  40105b:	0f b6 ca             	movzbl %dl,%ecx
  40105e:	21 c8                	and    %ecx,%eax
  401060:	c3                   	retq   

# end do_weird_calcs()

  401061:	66 66 66 66 66 66 2e 	data32 data32 data32 data32 data32 nopw %cs:0x0(%rax,%rax,1)
  401068:	0f 1f 84 00 00 00 00 
  40106f:	00 
  401070:	c7 44 24 fc 00 00 00 	movl   $0x0,-0x4(%rsp)
  401077:	00 
  401078:	81 7c 24 fc 9e 00 00 	cmpl   $0x9e,-0x4(%rsp)
  40107f:	00 
  401080:	0f 8d 3d 00 00 00    	jge    4010c3 <mprotect@plt+0x5a3>
  401086:	48 63 44 24 fc       	movslq -0x4(%rsp),%rax
  40108b:	0f b6 0c 05 00 28 40 	movzbl 0x402800(,%rax,1),%ecx
  401092:	00 
  401093:	0f b6 14 25 d3 27 40 	movzbl 0x4027d3,%edx
  40109a:	00 
  40109b:	31 d1                	xor    %edx,%ecx
  40109d:	40 88 ce             	mov    %cl,%sil
  4010a0:	48 63 44 24 fc       	movslq -0x4(%rsp),%rax
  4010a5:	48 8b 3c 25 00 2b 40 	mov    0x402b00,%rdi
  4010ac:	00 
  4010ad:	40 88 34 07          	mov    %sil,(%rdi,%rax,1)
  4010b1:	8b 44 24 fc          	mov    -0x4(%rsp),%eax
  4010b5:	05 01 00 00 00       	add    $0x1,%eax
  4010ba:	89 44 24 fc          	mov    %eax,-0x4(%rsp)
  4010be:	e9 b5 ff ff ff       	jmpq   401078 <mprotect@plt+0x558>
  4010c3:	c3                   	retq   
  4010c4:	66 66 66 2e 0f 1f 84 	data32 data32 nopw %cs:0x0(%rax,%rax,1)
  4010cb:	00 00 00 00 00 

# begin main()

  4010d0:	55                   	push   %rbp                         # frame setup
  4010d1:	48 89 e5             	mov    %rsp,%rbp
  4010d4:	48 83 ec 50          	sub    $0x50,%rsp                   # 0x50 bytes local variables
  4010d8:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)              # int ret = 0
  4010df:	e8 bc fe ff ff       	callq  400fa0 <mprotect@plt+0x480>  # do_weird_calcs()
  4010e4:	3d 00 00 00 00       	cmp    $0x0,%eax                    # if 0 returned
  4010e9:	0f 84 af 00 00 00    	je     40119e <mprotect@plt+0x67e>  # jump to print_and_exit
  4010ef:	e8 3c fb ff ff       	callq  400c30 <mprotect@plt+0x110>  # sha1_and_evp()
  4010f4:	48 8b 04 25 00 2b 40 	mov    0x402b00,%rax                # %rax = *0x402b00
  4010fb:	00 
  4010fc:	81 38 eb 6e 0a 54    	cmpl   $0x540a6eeb,(%rax)           # if *%rax == 0x540a6eeb
  401102:	0f 84 7d 00 00 00    	je     401185 <mprotect@plt+0x665>  # jump to indirect_fn_call

  401108:	48 8d 34 25 a0 12 40 	lea    0x4012a0,%rsi                # %rsi = 0x4012a0
  40110f:	00 
  401110:	48 ba 27 00 00 00 00 	movabs $0x27,%rdx                   # %rdx = 0x27
  401117:	00 00 00 
  40111a:	48 8d 45 d0          	lea    -0x30(%rbp),%rax             
  40111e:	48 89 c7             	mov    %rax,%rdi                    # %rdi = %rbp - 0x30
  401121:	e8 6a f9 ff ff       	callq  400a90 <memcpy@plt>          # call memcpy(%rdi, %rsi, %rdx);
  401126:	c7 45 cc 00 00 00 00 	movl   $0x0,-0x34(%rbp)             # i = 0;
  40112d:	81 7d cc 26 00 00 00 	cmpl   $0x26,-0x34(%rbp)            # while (i < 0x26) {
  401134:	0f 8d 29 00 00 00    	jge    401163 <mprotect@plt+0x643>
  40113a:	48 63 45 cc          	movslq -0x34(%rbp),%rax             # %rax = i
  40113e:	0f be 4c 05 d0       	movsbl -0x30(%rbp,%rax,1),%ecx      # %ecx = ?, %edx = ?, %rax = 0, modify something on the stack which we just copied using memcpy. Actually, it sets the string buffer to "You just fucked with the wrong binary".
  401143:	81 f1 c4 00 00 00    	xor    $0xc4,%ecx
  401149:	88 ca                	mov    %cl,%dl
  40114b:	48 63 45 cc          	movslq -0x34(%rbp),%rax
  40114f:	88 54 05 d0          	mov    %dl,-0x30(%rbp,%rax,1)
  401153:	8b 45 cc             	mov    -0x34(%rbp),%eax
  401156:	05 01 00 00 00       	add    $0x1,%eax
  40115b:	89 45 cc             	mov    %eax,-0x34(%rbp)
  40115e:	e9 ca ff ff ff       	jmpq   40112d <mprotect@plt+0x60d> # } // end while
  401163:	48 8d 3c 25 c7 12 40 	lea    0x4012c7,%rdi                # %rdi = "%s\n"
  40116a:	00 
  40116b:	48 8d 75 d0          	lea    -0x30(%rbp),%rsi             # %rsi = the string
  40116f:	b0 00                	mov    $0x0,%al
  401171:	e8 2a f9 ff ff       	callq  400aa0 <printf@plt>          # printf(%rdi, $rsi);
  401176:	c7 45 fc 01 00 00 00 	movl   $0x1,-0x4(%rbp)
  40117d:	89 45 bc             	mov    %eax,-0x44(%rbp)
  401180:	e9 2b 00 00 00       	jmpq   4011b0 <mprotect@plt+0x690>  # jump to exit_app

# indirect_fn_call (still in main())

  401185:	48 8b 04 25 00 2b 40 	mov    0x402b00,%rax            # %rax = *0x402b00
  40118c:	00 
  40118d:	48 89 45 c0          	mov    %rax,-0x40(%rbp)         
  401191:	b0 00                	mov    $0x0,%al
  401193:	ff 55 c0             	callq  *-0x40(%rbp)             # call function at **0x402b00; with gettimeofday() fixed, this evaluates to 0x404000: f2()
  401196:	89 45 b8             	mov    %eax,-0x48(%rbp)         # store result on stack
  401199:	e9 12 00 00 00       	jmpq   4011b0 <mprotect@plt+0x690>  # jump to exit_app

# begin f2() from dynamic code segment:

   0x404000:    jmp    0x404070             # goto f2l1

# f2l1:

=> 0x404070:    xor    %rax,%rax
   0x404073:    xor    %rdi,%rdi
   0x404076:    xor    %rdx,%rdx
   0x404079:    add    $0x1,%rax
   0x40407d:    add    $0x1,%rdi
   0x404081:    lea    -0x5c(%rip),%rsi        # 0x40402c
   0x404088:    add    $0x44,%rdx
   0x40408c:    syscall             # syscall(%rdi, %rsi, %rdx); write(STDOUT_FILENO, 0x40402c, 0x44); 0x40402c: This is not the secret you are looking for...
   0x40408e:    xor    %rax,%rax
   0x404091:    add    $0x3c,%rax
   0x404095:    xor    %rdi,%rdi
   0x404098:    syscall             # exit(0)

# end f2()

# print_and_exit1 (in main())

  40119e:	48 8d 3c 25 e5 12 40 	lea    0x4012e5,%rdi
  4011a5:	00 
  4011a6:	b0 00                	mov    $0x0,%al
  4011a8:	e8 f3 f8 ff ff       	callq  400aa0 <printf@plt>
  4011ad:	89 45 b4             	mov    %eax,-0x4c(%rbp)

# exit_app (in main())

  4011b0:	8b 45 fc             	mov    -0x4(%rbp),%eax
  4011b3:	48 83 c4 50          	add    $0x50,%rsp
  4011b7:	5d                   	pop    %rbp
  4011b8:	c3                   	retq   

  4011b9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

# begin init(), called before main()

  4011c0:	41 57                	push   %r15
  4011c2:	41 89 ff             	mov    %edi,%r15d
  4011c5:	41 56                	push   %r14
  4011c7:	49 89 f6             	mov    %rsi,%r14
  4011ca:	41 55                	push   %r13
  4011cc:	49 89 d5             	mov    %rdx,%r13
  4011cf:	41 54                	push   %r12
  4011d1:	4c 8d 25 10 19 00 00 	lea    0x1910(%rip),%r12        # 402ae8 <_fini+0x18b4>
  4011d8:	55                   	push   %rbp
  4011d9:	48 8d 2d 18 19 00 00 	lea    0x1918(%rip),%rbp        # 402af8 <__bss_start>
  4011e0:	53                   	push   %rbx
  4011e1:	4c 29 e5             	sub    %r12,%rbp
  4011e4:	31 db                	xor    %ebx,%ebx
  4011e6:	48 c1 fd 03          	sar    $0x3,%rbp
  4011ea:	48 83 ec 08          	sub    $0x8,%rsp
  4011ee:	e8 c5 f7 ff ff       	callq  4009b8 <_init>
  4011f3:	48 85 ed             	test   %rbp,%rbp
  4011f6:	74 1e                	je     401216 <mprotect@plt+0x6f6>
  4011f8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  4011ff:	00 
  401200:	4c 89 ea             	mov    %r13,%rdx                # ~ while ... {
  401203:	4c 89 f6             	mov    %r14,%rsi
  401206:	44 89 ff             	mov    %r15d,%edi
  401209:	41 ff 14 dc          	callq  *(%r12,%rbx,8)           # call initializers: f0() andf1() which sets up 0x402b00
  40120d:	48 83 c3 01          	add    $0x1,%rbx
  401211:	48 39 eb             	cmp    %rbp,%rbx
  401214:	75 ea                	jne    401200 <mprotect@plt+0x6e0> # }
  401216:	48 83 c4 08          	add    $0x8,%rsp
  40121a:	5b                   	pop    %rbx
  40121b:	5d                   	pop    %rbp
  40121c:	41 5c                	pop    %r12
  40121e:	41 5d                	pop    %r13
  401220:	41 5e                	pop    %r14
  401222:	41 5f                	pop    %r15
  401224:	c3                   	retq                            # return to __libc_start_main

# end init()

  401225:	66 66 2e 0f 1f 84 00 	data32 nopw %cs:0x0(%rax,%rax,1)
  40122c:	00 00 00 00 

# begin atexit()

  401230:	f3 c3                	repz retq                       # empty function
  401232:	66 90                	xchg   %ax,%ax

Disassembly of section .fini:

0000000000401234 <_fini>:
  401234:	48 83 ec 08          	sub    $0x8,%rsp
  401238:	48 83 c4 08          	add    $0x8,%rsp
  40123c:	c3                   	retq   

Disassembly of section .rodata:

0000000000401240 <.rodata>:
  401240:	01 00                	add    %eax,(%rax)
  401242:	02 00                	add    (%rax),%al
	...
  401250:	00 01                	add    %al,(%rcx)
  401252:	02 03                	add    (%rbx),%al
  401254:	04 05                	add    $0x5,%al
  401256:	06                   	(bad)  
  401257:	07                   	(bad)  
  401258:	08 09                	or     %cl,(%rcx)
  40125a:	0a 0b                	or     (%rbx),%cl
  40125c:	0c 0d                	or     $0xd,%al
  40125e:	0e                   	(bad)  
  40125f:	0f 00 00             	sldt   (%rax)
	...
  40126e:	00 00                	add    %al,(%rax)
  401270:	e6 ce                	out    %al,$0xce
  401272:	d8 d8                	fcomp  %st(0)
  401274:	8b dc                	mov    %esp,%ebx
  401276:	c2 df c3             	retq   $0xc3df
  401279:	8b df                	mov    %edi,%ebx
  40127b:	c3                   	retq   
  40127c:	ce                   	(bad)  
  40127d:	8b c9                	mov    %ecx,%ecx
  40127f:	ce                   	(bad)  
  401280:	d8 df                	fcomp  %st(7)
  401282:	87 8b cf c2 ce 8b    	xchg   %ecx,-0x74313d31(%rbx)
  401288:	c7 c2 c0 ce 8b df    	mov    $0xdf8bcec0,%edx
  40128e:	c3                   	retq   
  40128f:	ce                   	(bad)  
  401290:	8b d9                	mov    %ecx,%ebx
  401292:	ce                   	(bad)  
  401293:	d8 df                	fcomp  %st(7)
  401295:	85 00                	test   %eax,(%rax)
	...
  40129f:	00 9d ab b1 e4 ae    	add    %bl,-0x511b4e55(%rbp)
  4012a5:	b1 b7                	mov    $0xb7,%cl
  4012a7:	b0 e4                	mov    $0xe4,%al
  4012a9:	a2 b1 a7 af a1 a0 e4 	movabs %al,0xadb3e4a0a1afa7b1
  4012b0:	b3 ad 
  4012b2:	b0 ac                	mov    $0xac,%al
  4012b4:	e4 b0                	in     $0xb0,%al
  4012b6:	ac                   	lods   %ds:(%rsi),%al
  4012b7:	a1 e4 b3 b6 ab aa a3 	movabs 0xa6e4a3aaabb6b3e4,%eax
  4012be:	e4 a6 
  4012c0:	ad                   	lods   %ds:(%rsi),%eax
  4012c1:	aa                   	stos   %al,%es:(%rdi)
  4012c2:	a5                   	movsl  %ds:(%rsi),%es:(%rdi)
  4012c3:	b6 bd                	mov    $0xbd,%dh
  4012c5:	e5 00                	in     $0x0,%eax
  4012c7:	25 73 0a 00 73       	and    $0x73000a73,%eax     "%s\n"
  4012cc:	79 73                	jns    401341 <_fini+0x10d>
  4012ce:	63 6f 6e             	movslq 0x6e(%rdi),%ebp
  4012d1:	66                   	data16
  4012d2:	00 6d 65             	add    %ch,0x65(%rbp)
  4012d5:	6d                   	insl   (%dx),%es:(%rdi)
  4012d6:	61                   	(bad)  
  4012d7:	6c                   	insb   (%dx),%es:(%rdi)
  4012d8:	69 67 6e 00 6d 70 72 	imul   $0x72706d00,0x6e(%rdi),%esp
  4012df:	6f                   	outsl  %ds:(%rsi),(%dx)
  4012e0:	74 65                	je     401347 <_fini+0x113>
  4012e2:	63 74 00 27          	movslq 0x27(%rax,%rax,1),%esi
  4012e6:	61                   	(bad)  
  4012e7:	72 6c                	jb     401355 <_fini+0x121>
  4012e9:	6f                   	outsl  %ds:(%rsi),(%dx)
  4012ea:	67 68 20 51 6f 79    	addr32 pushq $0x796f5120
  4012f0:	6c                   	insb   (%dx),%es:(%rdi)
  4012f1:	75 27                	jne    40131a <_fini+0xe6>
  4012f3:	70 75                	jo     40136a <_fini+0x136>
  4012f5:	27                   	(bad)  
  4012f6:	3f                   	(bad)  
  4012f7:	0a 00                	or     (%rax),%al

Disassembly of section .eh_frame:

0000000000401300 <.eh_frame>:
  401300:	14 00                	adc    $0x0,%al
  401302:	00 00                	add    %al,(%rax)
  401304:	00 00                	add    %al,(%rax)
  401306:	00 00                	add    %al,(%rax)
  401308:	01 7a 52             	add    %edi,0x52(%rdx)
  40130b:	00 01                	add    %al,(%rcx)
  40130d:	78 10                	js     40131f <_fini+0xeb>
  40130f:	01 1b                	add    %ebx,(%rbx)
  401311:	0c 07                	or     $0x7,%al
  401313:	08 90 01 00 00 14    	or     %dl,0x14000001(%rax)
  401319:	00 00                	add    %al,(%rax)
  40131b:	00 1c 00             	add    %bl,(%rax,%rax,1)
  40131e:	00 00                	add    %al,(%rax)
  401320:	00 f9                	add    %bh,%cl
  401322:	ff                   	(bad)  
  401323:	ff 05 00 00 00 00    	incl   0x0(%rip)        # 401329 <_fini+0xf5>
  401329:	00 00                	add    %al,(%rax)
  40132b:	00 00                	add    %al,(%rax)
  40132d:	00 00                	add    %al,(%rax)
  40132f:	00 1c 00             	add    %bl,(%rax,%rax,1)
  401332:	00 00                	add    %al,(%rax)
  401334:	34 00                	xor    $0x0,%al
  401336:	00 00                	add    %al,(%rax)
  401338:	f8                   	clc    
  401339:	f8                   	clc    
  40133a:	ff                   	(bad)  
  40133b:	ff                   	(bad)  
  40133c:	7e 01                	jle    40133f <_fini+0x10b>
  40133e:	00 00                	add    %al,(%rax)
  401340:	00 41 0e             	add    %al,0xe(%rcx)
  401343:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  401349:	00 00                	add    %al,(%rax)
  40134b:	00 00                	add    %al,(%rax)
  40134d:	00 00                	add    %al,(%rax)
  40134f:	00 14 00             	add    %dl,(%rax,%rax,1)
  401352:	00 00                	add    %al,(%rax)
  401354:	54                   	push   %rsp
  401355:	00 00                	add    %al,(%rax)
  401357:	00 58 fa             	add    %bl,-0x6(%rax)
  40135a:	ff                   	(bad)  
  40135b:	ff 05 00 00 00 00    	incl   0x0(%rip)        # 401361 <_fini+0x12d>
  401361:	00 00                	add    %al,(%rax)
  401363:	00 00                	add    %al,(%rax)
  401365:	00 00                	add    %al,(%rax)
  401367:	00 1c 00             	add    %bl,(%rax,%rax,1)
  40136a:	00 00                	add    %al,(%rax)
  40136c:	6c                   	insb   (%dx),%es:(%rdi)
  40136d:	00 00                	add    %al,(%rax)
  40136f:	00 50 fa             	add    %dl,-0x6(%rax)
  401372:	ff                   	(bad)  
  401373:	ff ac 00 00 00 00 41 	ljmpq  *0x41000000(%rax,%rax,1)
  40137a:	0e                   	(bad)  
  40137b:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  401381:	00 00                	add    %al,(%rax)
  401383:	00 00                	add    %al,(%rax)
  401385:	00 00                	add    %al,(%rax)
  401387:	00 1c 00             	add    %bl,(%rax,%rax,1)
  40138a:	00 00                	add    %al,(%rax)
  40138c:	8c 00                	mov    %es,(%rax)
  40138e:	00 00                	add    %al,(%rax)
  401390:	e0 fa                	loopne 40138c <_fini+0x158>
  401392:	ff                   	(bad)  
  401393:	ff 2e                	ljmpq  *(%rsi)
  401395:	01 00                	add    %eax,(%rax)
  401397:	00 00                	add    %al,(%rax)
  401399:	41 0e                	rex.B (bad) 
  40139b:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  4013a1:	00 00                	add    %al,(%rax)
  4013a3:	00 00                	add    %al,(%rax)
  4013a5:	00 00                	add    %al,(%rax)
  4013a7:	00 14 00             	add    %dl,(%rax,%rax,1)
  4013aa:	00 00                	add    %al,(%rax)
  4013ac:	ac                   	lods   %ds:(%rsi),%al
  4013ad:	00 00                	add    %al,(%rax)
  4013af:	00 f0                	add    %dh,%al
  4013b1:	fb                   	sti    
  4013b2:	ff                   	(bad)  
  4013b3:	ff c1                	inc    %ecx
	...
  4013bd:	00 00                	add    %al,(%rax)
  4013bf:	00 14 00             	add    %dl,(%rax,%rax,1)
  4013c2:	00 00                	add    %al,(%rax)
  4013c4:	c4                   	(bad)  
  4013c5:	00 00                	add    %al,(%rax)
  4013c7:	00 a8 fc ff ff 54    	add    %ch,0x54fffffc(%rax)
	...
  4013d5:	00 00                	add    %al,(%rax)
  4013d7:	00 1c 00             	add    %bl,(%rax,%rax,1)
  4013da:	00 00                	add    %al,(%rax)
  4013dc:	dc 00                	faddl  (%rax)
  4013de:	00 00                	add    %al,(%rax)
  4013e0:	f0 fc                	lock cld 
  4013e2:	ff                   	(bad)  
  4013e3:	ff e9                	ljmpq  *<internal disassembler error>
  4013e5:	00 00                	add    %al,(%rax)
  4013e7:	00 00                	add    %al,(%rax)
  4013e9:	41 0e                	rex.B (bad) 
  4013eb:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  4013f1:	00 00                	add    %al,(%rax)
  4013f3:	00 00                	add    %al,(%rax)
  4013f5:	00 00                	add    %al,(%rax)
  4013f7:	00 44 00 00          	add    %al,0x0(%rax,%rax,1)
  4013fb:	00 fc                	add    %bh,%ah
  4013fd:	00 00                	add    %al,(%rax)
  4013ff:	00 c0                	add    %al,%al
  401401:	fd                   	std    
  401402:	ff                   	(bad)  
  401403:	ff 65 00             	jmpq   *0x0(%rbp)
  401406:	00 00                	add    %al,(%rax)
  401408:	00 42 0e             	add    %al,0xe(%rdx)
  40140b:	10 8f 02 45 0e 18    	adc    %cl,0x180e4502(%rdi)
  401411:	8e 03                	mov    (%rbx),%es
  401413:	45 0e                	rex.RB (bad) 
  401415:	20 8d 04 45 0e 28    	and    %cl,0x280e4504(%rbp)
  40141b:	8c 05 48 0e 30 86    	mov    %es,-0x79cff1b8(%rip)        # ffffffff86702269 <_end+0xffffffff862ff761>
  401421:	06                   	(bad)  
  401422:	48 0e                	rex.W (bad) 
  401424:	38 83 07 4d 0e 40    	cmp    %al,0x400e4d07(%rbx)
  40142a:	6c                   	insb   (%dx),%es:(%rdi)
  40142b:	0e                   	(bad)  
  40142c:	38 41 0e             	cmp    %al,0xe(%rcx)
  40142f:	30 41 0e             	xor    %al,0xe(%rcx)
  401432:	28 42 0e             	sub    %al,0xe(%rdx)
  401435:	20 42 0e             	and    %al,0xe(%rdx)
  401438:	18 42 0e             	sbb    %al,0xe(%rdx)
  40143b:	10 42 0e             	adc    %al,0xe(%rdx)
  40143e:	08 00                	or     %al,(%rax)
  401440:	14 00                	adc    $0x0,%al
  401442:	00 00                	add    %al,(%rax)
  401444:	44 01 00             	add    %r8d,(%rax)
  401447:	00 e8                	add    %ch,%al
  401449:	fd                   	std    
  40144a:	ff                   	(bad)  
  40144b:	ff 02                	incl   (%rdx)
	...
  401455:	00 00                	add    %al,(%rax)
  401457:	00 24 00             	add    %ah,(%rax,%rax,1)
  40145a:	00 00                	add    %al,(%rax)
  40145c:	5c                   	pop    %rsp
  40145d:	01 00                	add    %eax,(%rax)
  40145f:	00 80 f5 ff ff 50    	add    %al,0x50fffff5(%rax)
  401465:	01 00                	add    %eax,(%rax)
  401467:	00 00                	add    %al,(%rax)
  401469:	0e                   	(bad)  
  40146a:	10 46 0e             	adc    %al,0xe(%rsi)
  40146d:	18 4a 0f             	sbb    %cl,0xf(%rdx)
  401470:	0b 77 08             	or     0x8(%rdi),%esi
  401473:	80 00 3f             	addb   $0x3f,(%rax)
  401476:	1a 3b                	sbb    (%rbx),%bh
  401478:	2a 33                	sub    (%rbx),%dh
  40147a:	24 22                	and    $0x22,%al
  40147c:	00 00                	add    %al,(%rax)
  40147e:	00 00                	add    %al,(%rax)
  401480:	14 00                	adc    $0x0,%al
  401482:	00 00                	add    %al,(%rax)
  401484:	00 00                	add    %al,(%rax)
  401486:	00 00                	add    %al,(%rax)
  401488:	01 7a 52             	add    %edi,0x52(%rdx)
  40148b:	00 01                	add    %al,(%rcx)
  40148d:	78 10                	js     40149f <_fini+0x26b>
  40148f:	01 1b                	add    %ebx,(%rbx)
  401491:	0c 07                	or     $0x7,%al
  401493:	08 90 01 07 10 14    	or     %dl,0x14100701(%rax)
  401499:	00 00                	add    %al,(%rax)
  40149b:	00 1c 00             	add    %bl,(%rax,%rax,1)
  40149e:	00 00                	add    %al,(%rax)
  4014a0:	90                   	nop
  4014a1:	f6 ff                	idiv   %bh
  4014a3:	ff 2a                	ljmpq  *(%rdx)
	...

Disassembly of section .eh_frame_hdr:

00000000004014b4 <.eh_frame_hdr>:
  4014b4:	01 1b                	add    %ebx,(%rbx)
  4014b6:	03 3b                	add    (%rbx),%edi
  4014b8:	48 fe                	rex.W (bad) 
  4014ba:	ff                   	(bad)  
  4014bb:	ff 0c 00             	decl   (%rax,%rax,1)
  4014be:	00 00                	add    %al,(%rax)
  4014c0:	2c f5                	sub    $0xf5,%al
  4014c2:	ff                   	(bad)  
  4014c3:	ff a4 ff ff ff 7c f6 	jmpq   *-0x9830001(%rdi,%rdi,8)
  4014ca:	ff                   	(bad)  
  4014cb:	ff e4                	jmpq   *%rsp
  4014cd:	ff                   	(bad)  
  4014ce:	ff                   	(bad)  
  4014cf:	ff 6c f7 ff          	ljmpq  *-0x1(%rdi,%rsi,8)
  4014d3:	ff 64 fe ff          	jmpq   *-0x1(%rsi,%rdi,8)
  4014d7:	ff                   	(bad)  
  4014d8:	7c f7                	jl     4014d1 <_fini+0x29d>
  4014da:	ff                   	(bad)  
  4014db:	ff                   	(bad)  
  4014dc:	7c fe                	jl     4014dc <_fini+0x2a8>
  4014de:	ff                   	(bad)  
  4014df:	ff                   	(bad)  
  4014e0:	fc                   	cld    
  4014e1:	f8                   	clc    
  4014e2:	ff                   	(bad)  
  4014e3:	ff 9c fe ff ff 0c f9 	lcallq *-0x6f30001(%rsi,%rdi,8)
  4014ea:	ff                   	(bad)  
  4014eb:	ff b4 fe ff ff bc f9 	pushq  -0x6430001(%rsi,%rdi,8)
  4014f2:	ff                   	(bad)  
  4014f3:	ff d4                	callq  *%rsp
  4014f5:	fe                   	(bad)  
  4014f6:	ff                   	(bad)  
  4014f7:	ff ec                	ljmpq  *<internal disassembler error>
  4014f9:	fa                   	cli    
  4014fa:	ff                   	(bad)  
  4014fb:	ff f4                	push   %rsp
  4014fd:	fe                   	(bad)  
  4014fe:	ff                   	(bad)  
  4014ff:	ff                   	(bad)  
  401500:	bc fb ff ff 0c       	mov    $0xcfffffb,%esp
  401505:	ff                   	(bad)  
  401506:	ff                   	(bad)  
  401507:	ff 1c fc             	lcallq *(%rsp,%rdi,8)
  40150a:	ff                   	(bad)  
  40150b:	ff 24 ff             	jmpq   *(%rdi,%rdi,8)
  40150e:	ff                   	(bad)  
  40150f:	ff 0c fd ff ff 44 ff 	decl   -0xbb0001(,%rdi,8)
  401516:	ff                   	(bad)  
  401517:	ff                   	(bad)  
  401518:	7c fd                	jl     401517 <_fini+0x2e3>
  40151a:	ff                   	(bad)  
  40151b:	ff                   	.byte 0xff
  40151c:	8c ff                	mov    %?,%edi
  40151e:	ff                   	(bad)  
  40151f:	ff                   	.byte 0xff

Disassembly of section .dynamic:

0000000000402520 <.dynamic>:
  402520:	03 00                	add    (%rax),%eax
  402522:	00 00                	add    %al,(%rax)
  402524:	00 00                	add    %al,(%rax)
  402526:	00 00                	add    %al,(%rax)
  402528:	08 27                	or     %ah,(%rdi)
  40252a:	40 00 00             	add    %al,(%rax)
  40252d:	00 00                	add    %al,(%rax)
  40252f:	00 02                	add    %al,(%rdx)
  402531:	00 00                	add    %al,(%rax)
  402533:	00 00                	add    %al,(%rax)
  402535:	00 00                	add    %al,(%rax)
  402537:	00 e0                	add    %ah,%al
  402539:	01 00                	add    %eax,(%rax)
  40253b:	00 00                	add    %al,(%rax)
  40253d:	00 00                	add    %al,(%rax)
  40253f:	00 17                	add    %dl,(%rdi)
  402541:	00 00                	add    %al,(%rax)
  402543:	00 00                	add    %al,(%rax)
  402545:	00 00                	add    %al,(%rax)
  402547:	00 d8                	add    %bl,%al
  402549:	07                   	(bad)  
  40254a:	40 00 00             	add    %al,(%rax)
  40254d:	00 00                	add    %al,(%rax)
  40254f:	00 14 00             	add    %dl,(%rax,%rax,1)
  402552:	00 00                	add    %al,(%rax)
  402554:	00 00                	add    %al,(%rax)
  402556:	00 00                	add    %al,(%rax)
  402558:	07                   	(bad)  
  402559:	00 00                	add    %al,(%rax)
  40255b:	00 00                	add    %al,(%rax)
  40255d:	00 00                	add    %al,(%rax)
  40255f:	00 07                	add    %al,(%rdi)
  402561:	00 00                	add    %al,(%rax)
  402563:	00 00                	add    %al,(%rax)
  402565:	00 00                	add    %al,(%rax)
  402567:	00 c0                	add    %al,%al
  402569:	07                   	(bad)  
  40256a:	40 00 00             	add    %al,(%rax)
  40256d:	00 00                	add    %al,(%rax)
  40256f:	00 08                	add    %cl,(%rax)
  402571:	00 00                	add    %al,(%rax)
  402573:	00 00                	add    %al,(%rax)
  402575:	00 00                	add    %al,(%rax)
  402577:	00 18                	add    %bl,(%rax)
  402579:	00 00                	add    %al,(%rax)
  40257b:	00 00                	add    %al,(%rax)
  40257d:	00 00                	add    %al,(%rax)
  40257f:	00 09                	add    %cl,(%rcx)
  402581:	00 00                	add    %al,(%rax)
  402583:	00 00                	add    %al,(%rax)
  402585:	00 00                	add    %al,(%rax)
  402587:	00 18                	add    %bl,(%rax)
  402589:	00 00                	add    %al,(%rax)
  40258b:	00 00                	add    %al,(%rax)
  40258d:	00 00                	add    %al,(%rax)
  40258f:	00 15 00 00 00 00    	add    %dl,0x0(%rip)        # 402595 <_fini+0x1361>
	...
  40259d:	00 00                	add    %al,(%rax)
  40259f:	00 06                	add    %al,(%rsi)
  4025a1:	00 00                	add    %al,(%rax)
  4025a3:	00 00                	add    %al,(%rax)
  4025a5:	00 00                	add    %al,(%rax)
  4025a7:	00 40 02             	add    %al,0x2(%rax)
  4025aa:	40 00 00             	add    %al,(%rax)
  4025ad:	00 00                	add    %al,(%rax)
  4025af:	00 0b                	add    %cl,(%rbx)
  4025b1:	00 00                	add    %al,(%rax)
  4025b3:	00 00                	add    %al,(%rax)
  4025b5:	00 00                	add    %al,(%rax)
  4025b7:	00 18                	add    %bl,(%rax)
  4025b9:	00 00                	add    %al,(%rax)
  4025bb:	00 00                	add    %al,(%rax)
  4025bd:	00 00                	add    %al,(%rax)
  4025bf:	00 05 00 00 00 00    	add    %al,0x0(%rip)        # 4025c5 <_fini+0x1391>
  4025c5:	00 00                	add    %al,(%rax)
  4025c7:	00 f8                	add    %bh,%al
  4025c9:	04 40                	add    $0x40,%al
  4025cb:	00 00                	add    %al,(%rax)
  4025cd:	00 00                	add    %al,(%rax)
  4025cf:	00 0a                	add    %cl,(%rdx)
  4025d1:	00 00                	add    %al,(%rax)
  4025d3:	00 00                	add    %al,(%rax)
  4025d5:	00 00                	add    %al,(%rax)
  4025d7:	00 92 01 00 00 00    	add    %dl,0x1(%rdx)
  4025dd:	00 00                	add    %al,(%rax)
  4025df:	00 04 00             	add    %al,(%rax,%rax,1)
  4025e2:	00 00                	add    %al,(%rax)
  4025e4:	00 00                	add    %al,(%rax)
  4025e6:	00 00                	add    %al,(%rax)
  4025e8:	90                   	nop
  4025e9:	06                   	(bad)  
  4025ea:	40 00 00             	add    %al,(%rax)
  4025ed:	00 00                	add    %al,(%rax)
  4025ef:	00 01                	add    %al,(%rcx)
  4025f1:	00 00                	add    %al,(%rax)
  4025f3:	00 00                	add    %al,(%rax)
  4025f5:	00 00                	add    %al,(%rax)
  4025f7:	00 7f 01             	add    %bh,0x1(%rdi)
  4025fa:	00 00                	add    %al,(%rax)
  4025fc:	00 00                	add    %al,(%rax)
  4025fe:	00 00                	add    %al,(%rax)
  402600:	01 00                	add    %eax,(%rax)
  402602:	00 00                	add    %al,(%rax)
  402604:	00 00                	add    %al,(%rax)
  402606:	00 00                	add    %al,(%rax)
  402608:	1f                   	(bad)  
  402609:	00 00                	add    %al,(%rax)
  40260b:	00 00                	add    %al,(%rax)
  40260d:	00 00                	add    %al,(%rax)
  40260f:	00 0c 00             	add    %cl,(%rax,%rax,1)
  402612:	00 00                	add    %al,(%rax)
  402614:	00 00                	add    %al,(%rax)
  402616:	00 00                	add    %al,(%rax)
  402618:	b8 09 40 00 00       	mov    $0x4009,%eax
  40261d:	00 00                	add    %al,(%rax)
  40261f:	00 0d 00 00 00 00    	add    %cl,0x0(%rip)        # 402625 <_fini+0x13f1>
  402625:	00 00                	add    %al,(%rax)
  402627:	00 34 12             	add    %dh,(%rdx,%rdx,1)
  40262a:	40 00 00             	add    %al,(%rax)
  40262d:	00 00                	add    %al,(%rax)
  40262f:	00 1a                	add    %bl,(%rdx)
  402631:	00 00                	add    %al,(%rax)
  402633:	00 00                	add    %al,(%rax)
  402635:	00 00                	add    %al,(%rax)
  402637:	00 e0                	add    %ah,%al
  402639:	2a 40 00             	sub    0x0(%rax),%al
  40263c:	00 00                	add    %al,(%rax)
  40263e:	00 00                	add    %al,(%rax)
  402640:	1c 00                	sbb    $0x0,%al
  402642:	00 00                	add    %al,(%rax)
  402644:	00 00                	add    %al,(%rax)
  402646:	00 00                	add    %al,(%rax)
  402648:	08 00                	or     %al,(%rax)
  40264a:	00 00                	add    %al,(%rax)
  40264c:	00 00                	add    %al,(%rax)
  40264e:	00 00                	add    %al,(%rax)
  402650:	19 00                	sbb    %eax,(%rax)
  402652:	00 00                	add    %al,(%rax)
  402654:	00 00                	add    %al,(%rax)
  402656:	00 00                	add    %al,(%rax)
  402658:	e8 2a 40 00 00       	callq  406687 <_end+0x3b7f>
  40265d:	00 00                	add    %al,(%rax)
  40265f:	00 1b                	add    %bl,(%rbx)
  402661:	00 00                	add    %al,(%rax)
  402663:	00 00                	add    %al,(%rax)
  402665:	00 00                	add    %al,(%rax)
  402667:	00 10                	add    %dl,(%rax)
  402669:	00 00                	add    %al,(%rax)
  40266b:	00 00                	add    %al,(%rax)
  40266d:	00 00                	add    %al,(%rax)
  40266f:	00 f0                	add    %dh,%al
  402671:	ff                   	(bad)  
  402672:	ff 6f 00             	ljmpq  *0x0(%rdi)
  402675:	00 00                	add    %al,(%rax)
  402677:	00 50 07             	add    %dl,0x7(%rax)
  40267a:	40 00 00             	add    %al,(%rax)
  40267d:	00 00                	add    %al,(%rax)
  40267f:	00 fe                	add    %bh,%dh
  402681:	ff                   	(bad)  
  402682:	ff 6f 00             	ljmpq  *0x0(%rdi)
  402685:	00 00                	add    %al,(%rax)
  402687:	00 8c 07 40 00 00 00 	add    %cl,0x40(%rdi,%rax,1)
  40268e:	00 00                	add    %al,(%rax)
  402690:	ff                   	(bad)  
  402691:	ff                   	(bad)  
  402692:	ff 6f 00             	ljmpq  *0x0(%rdi)
  402695:	00 00                	add    %al,(%rax)
  402697:	00 01                	add    %al,(%rcx)
	...

Disassembly of section .got:

0000000000402700 <.got>:
	...

Disassembly of section .got.plt:

0000000000402708 <.got.plt>:
  402708:	20 25 40 00 00 00    	and    %ah,0x40(%rip)        # 40274e <_fini+0x151a>
	...
  40271e:	00 00                	add    %al,(%rax)
  402720:	f6                   	(bad)  
  402721:	09 40 00             	or     %eax,0x0(%rax)
  402724:	00 00                	add    %al,(%rax)
  402726:	00 00                	add    %al,(%rax)
  402728:	06                   	(bad)  
  402729:	0a 40 00             	or     0x0(%rax),%al
  40272c:	00 00                	add    %al,(%rax)
  40272e:	00 00                	add    %al,(%rax)
  402730:	16                   	(bad)  
  402731:	0a 40 00             	or     0x0(%rax),%al
  402734:	00 00                	add    %al,(%rax)
  402736:	00 00                	add    %al,(%rax)
  402738:	26 0a 40 00          	or     %es:0x0(%rax),%al
  40273c:	00 00                	add    %al,(%rax)
  40273e:	00 00                	add    %al,(%rax)
  402740:	36 0a 40 00          	or     %ss:0x0(%rax),%al
  402744:	00 00                	add    %al,(%rax)
  402746:	00 00                	add    %al,(%rax)
  402748:	46 0a 40 00          	rex.RX or 0x0(%rax),%r8b
  40274c:	00 00                	add    %al,(%rax)
  40274e:	00 00                	add    %al,(%rax)
  402750:	56                   	push   %rsi
  402751:	0a 40 00             	or     0x0(%rax),%al
  402754:	00 00                	add    %al,(%rax)
  402756:	00 00                	add    %al,(%rax)
  402758:	66                   	data16
  402759:	0a 40 00             	or     0x0(%rax),%al
  40275c:	00 00                	add    %al,(%rax)
  40275e:	00 00                	add    %al,(%rax)
  402760:	76 0a                	jbe    40276c <_fini+0x1538>
  402762:	40 00 00             	add    %al,(%rax)
  402765:	00 00                	add    %al,(%rax)
  402767:	00 86 0a 40 00 00    	add    %al,0x400a(%rsi)
  40276d:	00 00                	add    %al,(%rax)
  40276f:	00 96 0a 40 00 00    	add    %dl,0x400a(%rsi)
  402775:	00 00                	add    %al,(%rax)
  402777:	00 a6 0a 40 00 00    	add    %ah,0x400a(%rsi)
  40277d:	00 00                	add    %al,(%rax)
  40277f:	00 b6 0a 40 00 00    	add    %dh,0x400a(%rsi)
  402785:	00 00                	add    %al,(%rax)
  402787:	00 c6                	add    %al,%dh
  402789:	0a 40 00             	or     0x0(%rax),%al
  40278c:	00 00                	add    %al,(%rax)
  40278e:	00 00                	add    %al,(%rax)
  402790:	d6                   	(bad)  
  402791:	0a 40 00             	or     0x0(%rax),%al
  402794:	00 00                	add    %al,(%rax)
  402796:	00 00                	add    %al,(%rax)
  402798:	e6 0a                	out    %al,$0xa
  40279a:	40 00 00             	add    %al,(%rax)
  40279d:	00 00                	add    %al,(%rax)
  40279f:	00 f6                	add    %dh,%dh
  4027a1:	0a 40 00             	or     0x0(%rax),%al
  4027a4:	00 00                	add    %al,(%rax)
  4027a6:	00 00                	add    %al,(%rax)
  4027a8:	06                   	(bad)  
  4027a9:	0b 40 00             	or     0x0(%rax),%eax
  4027ac:	00 00                	add    %al,(%rax)
  4027ae:	00 00                	add    %al,(%rax)
  4027b0:	16                   	(bad)  
  4027b1:	0b 40 00             	or     0x0(%rax),%eax
  4027b4:	00 00                	add    %al,(%rax)
  4027b6:	00 00                	add    %al,(%rax)
  4027b8:	26 0b 40 00          	or     %es:0x0(%rax),%eax
  4027bc:	00 00                	add    %al,(%rax)
	...

Disassembly of section .data:

00000000004027c0 <.data>:
	...
  4027d0:	ef                   	out    %eax,(%dx)
  4027d1:	be ad de 00 00       	mov    $0xdead,%esi
	...
  4027de:	00 00                	add    %al,(%rax)
  4027e0:	54                   	push   %rsp
  4027e1:	68 65 20 63 61       	pushq  $0x61632065
  4027e6:	6b 65 20 69          	imul   $0x69,0x20(%rbp),%esp
  4027ea:	73 20                	jae    40280c <_fini+0x15d8>
  4027ec:	61                   	(bad)  
  4027ed:	20 6c 69 65          	and    %ch,0x65(%rcx,%rbp,2)
  4027f1:	21 00                	and    %eax,(%rax)
	...
  4027ff:	00 80 8e f1 4e c4    	add    %al,-0x3bb10e72(%rax)
  402805:	08 14 a4             	or     %dl,(%rsp,%riz,4)
  402808:	77 a2                	ja     4027ac <_fini+0x1578>
  40280a:	b7 42                	mov    $0x42,%bh
  40280c:	5d                   	pop    %rbp
  40280d:	4b 15 f6 2a e2 84    	rex.WXB adc $0xffffffff84e22af6,%rax
  402813:	ef                   	out    %eax,(%dx)
  402814:	8c f5                	mov    %?,%ebp
  402816:	25 dc a6 5e 57       	and    $0x575ea6dc,%eax
  40281b:	3b ba 1e 54 67 0b    	cmp    0xb67541e(%rdx),%edi
  402821:	35 d9 53 1c 57       	xor    $0x571c53d9,%eax
  402826:	40                   	rex
  402827:	4c                   	rex.WR
  402828:	4d                   	rex.WRB
  402829:	f3 6c                	rep insb (%dx),%es:(%rdi)
  40282b:	ce                   	(bad)  
  40282c:	30 c1                	xor    %al,%cl
  40282e:	9c                   	pushfq 
  40282f:	f9                   	stc    
  402830:	20 27                	and    %ah,(%rdi)
  402832:	02 df                	add    %bh,%bl
  402834:	b4 9a                	mov    $0x9a,%ah
  402836:	59                   	pop    %rcx
  402837:	c9                   	leaveq 
  402838:	a0 e4 25 16 9d 37 23 	movabs 0x5a4323379d1625e4,%al
  40283f:	43 5a 
  402841:	28 37                	sub    %dh,(%rdi)
  402843:	ff                   	(bad)  
  402844:	b8 d7 23 c1 76       	mov    $0x76c123d7,%eax
  402849:	0a 3f                	or     (%rdi),%bh
  40284b:	8b 60 7c             	mov    0x7c(%rax),%esp
  40284e:	e3 22                	jrcxz  402872 <_fini+0x163e>
  402850:	c9                   	leaveq 
  402851:	28 ec                	sub    %ch,%ah
  402853:	dc 19                	fcompl (%rcx)
  402855:	d5                   	(bad)  
  402856:	3e                   	dsrex.XB
  402857:	43                   	rex.XB
  402858:	64                   	fs
  402859:	57                   	push   %rdi
  40285a:	fc                   	cld    
  40285b:	64                   	fs
  40285c:	40 8f                	rex (bad) 
  40285e:	22 22                	and    (%rdx),%ah
  402860:	b6 5f                	mov    $0x5f,%dh
  402862:	da 60 7b             	fisubl 0x7b(%rax)
  402865:	02 85 20 bd 8a ba    	add    -0x457542e0(%rbp),%al
  40286b:	0b a6 f3 22 26 7b    	or     0x7b2622f3(%rsi),%esp
  402871:	4e                   	rex.WRX
  402872:	43                   	rex.XB
  402873:	66                   	data16
  402874:	60                   	(bad)  
  402875:	6c                   	insb   (%dx),%es:(%rdi)
  402876:	72 c0                	jb     402838 <_fini+0x1604>
  402878:	7c 13                	jl     40288d <_fini+0x1659>
  40287a:	8b 07                	mov    (%rdi),%eax
  40287c:	2e 80 b0 e3 a7 79 a4 	xorb   $0x13,%cs:-0x5b86581d(%rax)
  402883:	13 
  402884:	c5 07 8a             	(bad)  
  402887:	ec                   	in     (%dx),%al
  402888:	ec                   	in     (%dx),%al
  402889:	0a 37                	or     (%rdi),%dh
  40288b:	cc                   	int3   
  40288c:	5e                   	pop    %rsi
  40288d:	7d 2c                	jge    4028bb <_fini+0x1687>
  40288f:	1a d1                	sbb    %cl,%dl
  402891:	42 53                	rex.X push %rbx
  402893:	96                   	xchg   %eax,%esi
  402894:	e9 a3 b7 7e 99       	jmpq   ffffffff99bee03c <_end+0xffffffff997eb534>
  402899:	4a 86 73 8f          	rex.WX xchg %sil,-0x71(%rbx)
  40289d:	5c                   	pop    %rsp
  40289e:	8d 80 00 00 00 00    	lea    0x0(%rax),%eax
	...
  4028b0:	57                   	push   %rdi
  4028b1:	69 74 68 20 77 61 72 	imul   $0x70726177,0x20(%rax,%rbp,2),%esi
  4028b8:	70 
  4028b9:	20 73 70             	and    %dh,0x70(%rbx)
  4028bc:	65 65 64 20 74 6f 20 	gs gs and %dh,%fs:%gs:0x20(%rdi,%rbp,2)
  4028c3:	74 68                	je     40292d <_fini+0x16f9>
  4028c5:	65 20 66 75          	and    %ah,%gs:0x75(%rsi)
  4028c9:	74 75                	je     402940 <_fini+0x170c>
  4028cb:	72 65                	jb     402932 <_fini+0x16fe>
  4028cd:	21 00                	and    %eax,(%rax)
  4028cf:	00 54 68 65          	add    %dl,0x65(%rax,%rbp,2)
  4028d3:	20 73 65             	and    %dh,0x65(%rbx)
  4028d6:	63 72 65             	movslq 0x65(%rdx),%esi
  4028d9:	74 20                	je     4028fb <_fini+0x16c7>
  4028db:	69 73 3a 20 00 54 68 	imul   $0x68540020,0x3a(%rbx),%esi
  4028e2:	65 20 72 65          	and    %dh,%gs:0x65(%rdx)
  4028e6:	61                   	(bad)  
  4028e7:	6c                   	insb   (%dx),%es:(%rdi)
  4028e8:	20 73 65             	and    %dh,0x65(%rbx)
  4028eb:	63 72 65             	movslq 0x65(%rdx),%esi
  4028ee:	74 20                	je     402910 <_fini+0x16dc>
  4028f0:	69 73 3a 20 00 00 00 	imul   $0x20,0x3a(%rbx),%esi
	...
  4028ff:	00 41 6e             	add    %al,0x6e(%rcx)
  402902:	64 20 6e 6f          	and    %ch,%fs:0x6f(%rsi)
  402906:	77 20                	ja     402928 <_fini+0x16f4>
  402908:	74 6f                	je     402979 <_fini+0x1745>
  40290a:	20 74 68 65          	and    %dh,0x65(%rax,%rbp,2)
  40290e:	20 72 65             	and    %dh,0x65(%rdx)
  402911:	61                   	(bad)  
  402912:	6c                   	insb   (%dx),%es:(%rdi)
  402913:	6c                   	insb   (%dx),%es:(%rdi)
  402914:	79 20                	jns    402936 <_fini+0x1702>
  402916:	72 65                	jb     40297d <_fini+0x1749>
  402918:	61                   	(bad)  
  402919:	6c                   	insb   (%dx),%es:(%rdi)
  40291a:	20 73 65             	and    %dh,0x65(%rbx)
  40291d:	63 72 65             	movslq 0x65(%rdx),%esi
  402920:	74 3a                	je     40295c <_fini+0x1728>
  402922:	20 00                	and    %al,(%rax)
	...
  402930:	54                   	push   %rsp
  402931:	68 65 20 6e 65       	pushq  $0x656e2065
  402936:	65                   	gs
  402937:	64                   	fs
  402938:	73 20                	jae    40295a <_fini+0x1726>
  40293a:	6f                   	outsl  %ds:(%rsi),(%dx)
  40293b:	66                   	data16
  40293c:	20 74 68 65          	and    %dh,0x65(%rax,%rbp,2)
  402940:	20 6d 61             	and    %ch,0x61(%rbp)
  402943:	6e                   	outsb  %ds:(%rsi),(%dx)
  402944:	79 20                	jns    402966 <_fini+0x1732>
  402946:	6f                   	outsl  %ds:(%rsi),(%dx)
  402947:	75 74                	jne    4029bd <_fini+0x1789>
  402949:	77 65                	ja     4029b0 <_fini+0x177c>
  40294b:	69 67 68 20 74 68 65 	imul   $0x65687420,0x68(%rdi),%esp
  402952:	20 6e 65             	and    %ch,0x65(%rsi)
  402955:	65                   	gs
  402956:	64                   	fs
  402957:	73 20                	jae    402979 <_fini+0x1745>
  402959:	6f                   	outsl  %ds:(%rsi),(%dx)
  40295a:	66                   	data16
  40295b:	20 74 68 65          	and    %dh,0x65(%rax,%rbp,2)
  40295f:	20 66 65             	and    %ah,0x65(%rsi)
  402962:	77 20                	ja     402984 <_fini+0x1750>
  402964:	6f                   	outsl  %ds:(%rsi),(%dx)
  402965:	72 20                	jb     402987 <_fini+0x1753>
  402967:	74 68                	je     4029d1 <_fini+0x179d>
  402969:	65 20 6f 6e          	and    %ch,%gs:0x6e(%rdi)
  40296d:	65 2e 00 20          	gs add %ah,%cs:%gs:(%rax)
  402971:	20 5f 20             	and    %bl,0x20(%rdi)
  402974:	20 20                	and    %ah,(%rax)
  402976:	5f                   	pop    %rdi
  402977:	20 5f 20             	and    %bl,0x20(%rdi)
  40297a:	20 20                	and    %ah,(%rax)
  40297c:	20 20                	and    %ah,(%rax)
  40297e:	20 20                	and    %ah,(%rax)
  402980:	20 20                	and    %ah,(%rax)
  402982:	20 20                	and    %ah,(%rax)
  402984:	20 5f 5f             	and    %bl,0x5f(%rdi)
  402987:	5f                   	pop    %rdi
  402988:	5f                   	pop    %rdi
  402989:	5f                   	pop    %rdi
  40298a:	5f                   	pop    %rdi
  40298b:	5f                   	pop    %rdi
  40298c:	20 20                	and    %ah,(%rax)
  40298e:	20 20                	and    %ah,(%rax)
  402990:	20 20                	and    %ah,(%rax)
  402992:	20 20                	and    %ah,(%rax)
  402994:	20 5f 20             	and    %bl,0x20(%rdi)
  402997:	0a 20                	or     (%rax),%ah
  402999:	7c 20                	jl     4029bb <_fini+0x1787>
  40299b:	5c                   	pop    %rsp
  40299c:	20 7c 20 28          	and    %bh,0x28(%rax,%riz,1)
  4029a0:	5f                   	pop    %rdi
  4029a1:	29 20                	sub    %esp,(%rax)
  4029a3:	20 20                	and    %ah,(%rax)
  4029a5:	20 20                	and    %ah,(%rax)
  4029a7:	20 20                	and    %ah,(%rax)
  4029a9:	20 20                	and    %ah,(%rax)
  4029ab:	20 7c 5f 5f          	and    %bh,0x5f(%rdi,%rbx,2)
  4029af:	20 20                	and    %ah,(%rax)
  4029b1:	20 5f 5f             	and    %bl,0x5f(%rdi)
  4029b4:	7c 20                	jl     4029d6 <_fini+0x17a2>
  4029b6:	20 20                	and    %ah,(%rax)
  4029b8:	20 20                	and    %ah,(%rax)
  4029ba:	20 20                	and    %ah,(%rax)
  4029bc:	7c 20                	jl     4029de <_fini+0x17aa>
  4029be:	7c 0a                	jl     4029ca <_fini+0x1796>
  4029c0:	20 7c 20 20          	and    %bh,0x20(%rax,%riz,1)
  4029c4:	5c                   	pop    %rsp
  4029c5:	7c 20                	jl     4029e7 <_fini+0x17b3>
  4029c7:	7c 5f                	jl     402a28 <_fini+0x17f4>
  4029c9:	20 20                	and    %ah,(%rax)
  4029cb:	5f                   	pop    %rdi
  4029cc:	5f                   	pop    %rdi
  4029cd:	5f                   	pop    %rdi
  4029ce:	20 5f 5f             	and    %bl,0x5f(%rdi)
  4029d1:	5f                   	pop    %rdi
  4029d2:	20 20                	and    %ah,(%rax)
  4029d4:	20 20                	and    %ah,(%rax)
  4029d6:	20 7c 20 7c          	and    %bh,0x7c(%rax,%riz,1)
  4029da:	5f                   	pop    %rdi
  4029db:	20 5f 5f             	and    %bl,0x5f(%rdi)
  4029de:	20 5f 20             	and    %bl,0x20(%rdi)
  4029e1:	20 20                	and    %ah,(%rax)
  4029e3:	5f                   	pop    %rdi
  4029e4:	7c 20                	jl     402a06 <_fini+0x17d2>
  4029e6:	7c 0a                	jl     4029f2 <_fini+0x17be>
  4029e8:	20 7c 20 2e          	and    %bh,0x2e(%rax,%riz,1)
  4029ec:	20 60 20             	and    %ah,0x20(%rax)
  4029ef:	7c 20                	jl     402a11 <_fini+0x17dd>
  4029f1:	7c 2f                	jl     402a22 <_fini+0x17ee>
  4029f3:	20 5f 5f             	and    %bl,0x5f(%rdi)
  4029f6:	2f                   	(bad)  
  4029f7:	20 5f 20             	and    %bl,0x20(%rdi)
  4029fa:	5c                   	pop    %rsp
  4029fb:	20 20                	and    %ah,(%rax)
  4029fd:	20 20                	and    %ah,(%rax)
  4029ff:	7c 20                	jl     402a21 <_fini+0x17ed>
  402a01:	7c 20                	jl     402a23 <_fini+0x17ef>
  402a03:	27                   	(bad)  
  402a04:	5f                   	pop    %rdi
  402a05:	5f                   	pop    %rdi
  402a06:	7c 20                	jl     402a28 <_fini+0x17f4>
  402a08:	7c 20                	jl     402a2a <_fini+0x17f6>
  402a0a:	7c 20                	jl     402a2c <_fini+0x17f8>
  402a0c:	7c 20                	jl     402a2e <_fini+0x17fa>
  402a0e:	7c 0a                	jl     402a1a <_fini+0x17e6>
  402a10:	20 7c 20 7c          	and    %bh,0x7c(%rax,%riz,1)
  402a14:	5c                   	pop    %rsp
  402a15:	20 20                	and    %ah,(%rax)
  402a17:	7c 20                	jl     402a39 <_fini+0x1805>
  402a19:	7c 20                	jl     402a3b <_fini+0x1807>
  402a1b:	28 5f 7c             	sub    %bl,0x7c(%rdi)
  402a1e:	20 20                	and    %ah,(%rax)
  402a20:	5f                   	pop    %rdi
  402a21:	5f                   	pop    %rdi
  402a22:	2f                   	(bad)  
  402a23:	20 20                	and    %ah,(%rax)
  402a25:	20 20                	and    %ah,(%rax)
  402a27:	7c 20                	jl     402a49 <_fini+0x1815>
  402a29:	7c 20                	jl     402a4b <_fini+0x1817>
  402a2b:	7c 20                	jl     402a4d <_fini+0x1819>
  402a2d:	20 7c 20 7c          	and    %bh,0x7c(%rax,%riz,1)
  402a31:	5f                   	pop    %rdi
  402a32:	7c 20                	jl     402a54 <_fini+0x1820>
  402a34:	7c 5f                	jl     402a95 <_fini+0x1861>
  402a36:	7c 0a                	jl     402a42 <_fini+0x180e>
  402a38:	20 7c 5f 7c          	and    %bh,0x7c(%rdi,%rbx,2)
  402a3c:	20 5c 5f 7c          	and    %bl,0x7c(%rdi,%rbx,2)
  402a40:	5f                   	pop    %rdi
  402a41:	7c 5c                	jl     402a9f <_fini+0x186b>
  402a43:	5f                   	pop    %rdi
  402a44:	5f                   	pop    %rdi
  402a45:	5f                   	pop    %rdi
  402a46:	5c                   	pop    %rsp
  402a47:	5f                   	pop    %rdi
  402a48:	5f                   	pop    %rdi
  402a49:	5f                   	pop    %rdi
  402a4a:	7c 20                	jl     402a6c <_fini+0x1838>
  402a4c:	20 20                	and    %ah,(%rax)
  402a4e:	20 7c 5f 7c          	and    %bh,0x7c(%rdi,%rbx,2)
  402a52:	5f                   	pop    %rdi
  402a53:	7c 20                	jl     402a75 <_fini+0x1841>
  402a55:	20 20                	and    %ah,(%rax)
  402a57:	5c                   	pop    %rsp
  402a58:	5f                   	pop    %rdi
  402a59:	5f                   	pop    %rdi
  402a5a:	2c 20                	sub    $0x20,%al
  402a5c:	28 5f 29             	sub    %bl,0x29(%rdi)
  402a5f:	0a 20                	or     (%rax),%ah
  402a61:	20 20                	and    %ah,(%rax)
  402a63:	20 20                	and    %ah,(%rax)
  402a65:	20 20                	and    %ah,(%rax)
  402a67:	20 20                	and    %ah,(%rax)
  402a69:	20 20                	and    %ah,(%rax)
  402a6b:	20 20                	and    %ah,(%rax)
  402a6d:	20 20                	and    %ah,(%rax)
  402a6f:	20 20                	and    %ah,(%rax)
  402a71:	20 20                	and    %ah,(%rax)
  402a73:	20 20                	and    %ah,(%rax)
  402a75:	20 20                	and    %ah,(%rax)
  402a77:	20 20                	and    %ah,(%rax)
  402a79:	20 20                	and    %ah,(%rax)
  402a7b:	20 20                	and    %ah,(%rax)
  402a7d:	20 20                	and    %ah,(%rax)
  402a7f:	20 5f 5f             	and    %bl,0x5f(%rdi)
  402a82:	2f                   	(bad)  
  402a83:	20 7c 20 20          	and    %bh,0x20(%rax,%riz,1)
  402a87:	0a 20                	or     (%rax),%ah
  402a89:	20 20                	and    %ah,(%rax)
  402a8b:	20 20                	and    %ah,(%rax)
  402a8d:	20 20                	and    %ah,(%rax)
  402a8f:	20 20                	and    %ah,(%rax)
  402a91:	20 20                	and    %ah,(%rax)
  402a93:	20 20                	and    %ah,(%rax)
  402a95:	20 20                	and    %ah,(%rax)
  402a97:	20 20                	and    %ah,(%rax)
  402a99:	20 20                	and    %ah,(%rax)
  402a9b:	20 20                	and    %ah,(%rax)
  402a9d:	20 20                	and    %ah,(%rax)
  402a9f:	20 20                	and    %ah,(%rax)
  402aa1:	20 20                	and    %ah,(%rax)
  402aa3:	20 20                	and    %ah,(%rax)
  402aa5:	20 20                	and    %ah,(%rax)
  402aa7:	7c 5f                	jl     402b08 <_end>
  402aa9:	5f                   	pop    %rdi
  402aaa:	5f                   	pop    %rdi
  402aab:	2f                   	(bad)  
  402aac:	20 20                	and    %ah,(%rax)
  402aae:	20 0a                	and    %cl,(%rdx)
	...
  402ac0:	4c 69 76 65 20 6c 6f 	imul   $0x6e6f6c20,0x65(%rsi),%r14
  402ac7:	6e 
  402ac8:	67 20 61 6e          	and    %ah,0x6e(%ecx)
  402acc:	64 20 70 72          	and    %dh,%fs:0x72(%rax)
  402ad0:	6f                   	outsl  %ds:(%rsi),(%dx)
  402ad1:	73 70                	jae    402b43 <_end+0x3b>
  402ad3:	65                   	gs
  402ad4:	72 2e                	jb     402b04 <__bss_start+0xc>
	...

Disassembly of section .jcr:

0000000000402ad8 <.jcr>:
	...

Disassembly of section .fini_array:

0000000000402ae0 <.fini_array>:
  402ae0:	d0 0b                	rorb   (%rbx)
  402ae2:	40 00 00             	add    %al,(%rax)
  402ae5:	00 00                	add    %al,(%rax)
	...

Disassembly of section .init_array:

0000000000402ae8 <.init_array>:
  402ae8:	f0 0b 40 00          	lock or 0x0(%rax),%eax
  402aec:	00 00                	add    %al,(%rax)
  402aee:	00 00                	add    %al,(%rax)
  402af0:	70 0e                	jo     402b00 <__bss_start+0x8>
  402af2:	40 00 00             	add    %al,(%rax)
  402af5:	00 00                	add    %al,(%rax)
	...

Disassembly of section .bss:

0000000000402af8 <.bss>:
	...

Disassembly of section .comment:

0000000000000000 <.comment>:
   0:	00 47 43             	add    %al,0x43(%rdi)
   3:	43 3a 20             	rex.XB cmp (%r8),%spl
   6:	28 47 4e             	sub    %al,0x4e(%rdi)
   9:	55                   	push   %rbp
   a:	29 20                	sub    %esp,(%rax)
   c:	34 2e                	xor    $0x2e,%al
   e:	38 2e                	cmp    %ch,(%rsi)
  10:	30 00                	xor    %al,(%rax)
  12:	47                   	rex.RXB
  13:	43                   	rex.XB
  14:	43 3a 20             	rex.XB cmp (%r8),%spl
  17:	28 47 4e             	sub    %al,0x4e(%rdi)
  1a:	55                   	push   %rbp
  1b:	29 20                	sub    %esp,(%rax)
  1d:	34 2e                	xor    $0x2e,%al
  1f:	38 2e                	cmp    %ch,(%rsi)
  21:	30 20                	xor    %ah,(%rax)
  23:	32 30                	xor    (%rax),%dh
  25:	31 33                	xor    %esi,(%rbx)
  27:	30 35 30 32 20 28    	xor    %dh,0x28203230(%rip)        # 2820325d <_end+0x27e00755>
  2d:	70 72                	jo     a1 <_init-0x400917>
  2f:	65                   	gs
  30:	72 65                	jb     97 <_init-0x400921>
  32:	6c                   	insb   (%dx),%es:(%rdi)
  33:	65                   	gs
  34:	61                   	(bad)  
  35:	73 65                	jae    9c <_init-0x40091c>
  37:	29 00                	sub    %eax,(%rax)

Disassembly of section .note.gnu.gold-version:

0000000000000000 <.note.gnu.gold-version>:
   0:	04 00                	add    $0x0,%al
   2:	00 00                	add    %al,(%rax)
   4:	09 00                	or     %eax,(%rax)
   6:	00 00                	add    %al,(%rax)
   8:	04 00                	add    $0x0,%al
   a:	00 00                	add    %al,(%rax)
   c:	47                   	rex.RXB
   d:	4e 55                	rex.WRX push %rbp
   f:	00 67 6f             	add    %ah,0x6f(%rdi)
  12:	6c                   	insb   (%dx),%es:(%rdi)
  13:	64 20 31             	and    %dh,%fs:(%rcx)
  16:	2e 31 31             	xor    %esi,%cs:(%rcx)
  19:	00 00                	add    %al,(%rax)
	...
