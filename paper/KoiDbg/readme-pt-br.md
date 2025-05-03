# Writing a Windows ARM64 Debugger for Reverse Engineering - KoiDbg

Author: João Vitor (@Keowu) - Security Researcher

## Introduction

O objetivo deste artigo é demonstrar as etapas de desenvolvimento de um debugger com foco em Windows ARM64. Não muito recentemente, tive o privilégio de analisar um caso bastante específico de ataque que afetava usuários do Windows ARM64 (do qual não posso dar detalhes devido a um NDA), o que me forçou a analisar tudo usando o WinDbg para ARM. Digamos que não foi a melhor das experiências — ainda mais para nós, pesquisadores de segurança, que estamos acostumados com o x64dbg ou outros debuggers similares. Esse fato despertou muito meu interesse sobre como debuggers funcionam e são criados.

Foi então que, em julho de 2024, iniciei paralelamente um projeto inicialmente chamado de HarukaMirai Dbg, que posteriormente viria a ser adquirido por uma empresa de segurança brasileira chamada Maldec Labs e renomeado para KoiDbg. Junto com o proprietário da empresa, um grande amigo de longa data, trabalhamos para concluir o projeto, que mais tarde seria publicado como código aberto no GitHub para a comunidade.

Este artigo trará muitas informações sobre o funcionamento do KoiDbg: experiências, detalhes, técnicas e o funcionamento completo de debuggers para Windows ARM64, além do desenvolvimento e análise de malwares para essa arquitetura, estruturas internas do sistema e muito mais.

![#0](/imgs/intro.png)

## Table of Contents

1. [Introduction](#introduction)
2. [Uma pequena mensagem antes de continuarmos](#uma-pequena-mensagem-antes-de-continuarmos)
3. [A saga de HarukaMiraiDbg até KoiDbg](#a-saga-de-harukamiraidbg-até-koidbg)
4. [Windows debuggers 101 - Qualquer arquitetura](#windows-debuggers-101---qualquer-arquitetura)
5. [KoiDbg Internals](#koidbg-internals)
    1. [KoiDbg Init-DebugLoop](#koidbg-init-debugloop)
        1. [handleExceptionDebugEvent](#handleexceptiondebugevent)
        2. [handleCreateThreadDebugEvent](#handlecreatethreaddebugevent)
        3. [handleCreateProcessDebugEvent](#handlecreateprocessdebugevent)
        4. [handleExitThreadDebugEvent](#handleexitthreaddebugevent)
        5. [handleExitProcessDebugEvent](#handleexitprocessdebugevent)
        6. [handleLoadDllDebugEvent](#handleloaddlldebugevent)
        7. [handleUnloadDllDebugEvent](#handleunloaddlldebugevent)
        8. [handleOutputDebugStringEvent](#handleoutputdebugstringevent)
        9. [handleRipEvent](#handleripevent)
    2. [KoiDbg Engine Functions](#koidbg-engine-functions)
        1. [ListAllHandleObjectsForDebugeeProcess](#listallhandleobjectsfordebugeeprocess)
        2. [AnalyseDebugProcessVirtualMemory](#analysedebugprocessvirtualmemory)
        3. [updateRegistersContext](#updateregisterscontext)
        4. [updateCallStackContext](#updatecallstackcontext)
        5. [updateStackContext](#updatestackcontext)
        6. [UpdateDisassemblerView](#updatedisassemblerview)
        7. [SetInterrupting](#setinterrupting)
        8. [RemoveInterrupting](#removeinterrupting)
        9. [UpdateActualIPContext](#updateactualipcontext)
        10. [stepInto](#stepinto)
        11. [stepOver](#stepover)
        12. [stepOut](#stepout)
        13. [DebugCommandProcessingLoop](#debugcommandprocessingloop)
        14. [SetNewPatch](#setnewpatch)
        15. [extractPdbFileFunctions](#extractpdbfilefunctions)
    3. [Kurumi Engine](#kurumi-engine)
        1. [Modularização](#modularização)
        2. [InitKurumiKOPDB](#initkurumikopdb)
        3. [DownloadKoiPdb](#downloadkoipdb)
        4. [FindPdbField](#findpdbfield)
        5. [FindPdbStructField](#findpdbstructfield)
        6. [ParsePdbFunctionsAndGetListInternal](#parsepdbfunctionsandgetlistinternal)
    4. [KoiDbg Utils](#koidbg-utils)
        1. [GetFileNameFromHandle](#getfilenamefromhandle)
        2. [symbol_from_address](#symbol_from_address)
        3. [GetDebuggerProcessHandleTable](#getdebuggerprocesshandletable)
        4. [GetRemoteHandleTableHandleInformation](#getremotehandletablehandleinformation)
        5. [GetDebuggerProcessHandleTable && GetRemoteHandleTableHandleInformation](#getdebuggerprocesshandletable--getremotehandletablehandleinformation)
    5. [Assembler Engine](#assembler-engine)
        1. [assembleX64Code && assembleArm64Code](#assemblex64code--assemblearm64code)
    6. [Disassembler Engine](#disassembler-engine)
        1. [RunCapstoneEnginex86 && RunCapstoneEngineAarch64](#runcapstoneenginex86--runcapstoneengineaarch64)
        2. [RunCapstoneForSingleStepARM64 && RunCapstoneForSingleStepx86](#runcapstoneforsinglesteparm64--runcapstoneforsinglestepx86)
        3. [RunCapstoneForStepOutARM64 && RunCapstoneForStepOutx86](#runcapstoneforsinglesteparm64--runcapstoneforsinglestepx86)
        4. [Syntaxe-Highlight Haruka](#syntaxe-highlight-haruka)
    7. [Extracting Windows Loader Struct Information - KoiDbg](#extracting-windows-loader-struct-information---koidbg)
        1. [extractLdrpVectorHandlerListInformation](#extractldrpvectorhandlerlistinformation)
        2. [extractNirvanaCallbackPresentOnDebugeeProcess](#extractnirvanacallbackpresentondebugeeprocess)
        3. [extractNtDelegateTableCallbacks](#extractntdelegatetablecallbacks)
            1. [Simple fields](#simple-fields)
            2. [RtlpDynamicFunctionTable](#rtlpdynamicfunctiontable)
            3. [LdrpDllNotificationList](#ldrpdllnotificationlist)
            4. [RtlpSecMemListHead](#rtlpsecmemlisthead)
            5. [KernelCallbackTable](#kernelcallbacktable)
    8. [Decompiler engine](#decompiler-engine)
    9. [Analisando um Packer para ARM64, revertendo e debugando com o KoiDbg](#analisando-um-packer-para-arm64-revertendo-e-debugando-com-o-koidbg)
        1. [Explorando a PEB no Windows ARM64 para escrever um loader](#explorando-a-peb-no-windows-arm64-para-escrever-um-loader)
            1. [Loader](#loader)
            2. [Shellcode](#shellcode)
            3. [PEB](#peb)
        2. [Analisando nosso código com o KoiDbg](#analisando-nosso-código-com-o-koidbg)
            1. [Shellcode Adventure](#shellcode-adventure)
    10. [KoiDbg Future](#koidbg-future)
    11. [Uma última mensagem](#uma-última-mensagem)
    12. [Referências](#referências)

#### Uma pequena mensagem antes de continuarmos

Nos últimos meses, estive muito ocupado: com projetos de amigos, trabalho, estudos/pesquisas, aprendendo e reforçando meu aprendizado de outros idiomas, outros projetos que estou tocando em segundo plano e até mesmo preparando material para outros artigos. E, claro, também descansando — porque ninguém é de ferro. Agradeço ao pessoal que me acompanha e que, de alguma forma, encontrou maneiras de entrar em contato: pelo Discord, e-mail, comentários no YouTube e até mesmo pessoalmente (mesmo eu nunca tendo mostrado meu rosto — bizarro, né?). Nunca imaginei que tantas pessoas gostassem de ler meus conteúdos. Sou muito grato a vocês. De verdade. Obrigado!

Deixo aqui um abraço especial para os amigos do Discord que acompanharam o desenvolvimento do projeto, participaram das pesquisas e revisaram este artigo de perto:

- rem0obb(https://github.com/rem0obb)
- Buzzer-re(https://github.com/buzzer-re)
- Lusty(https://github.com/lustywastaken)

E por fim, como de costume, uma recomendação de música para ouvir durante a leitura do artigo: [Legião Urbana - Tempo Perdido](https://www.youtube.com/watch?v=tI9kSZgMLsc).

**Atenção:** antes de continuar, tenha em mente que este artigo, apesar de bem detalhado e escrito em uma linguagem amigável para iniciantes em Engenharia Reversa/Windows Internals, pode não ser plenamente compreendido caso você não tenha uma base realmente **excelente em Engenharia Reversa ou Windows Internals.**

Desejo uma excelente leitura!

### A saga de HarukaMiraiDbg até KoiDbg

Quando iniciei o desenvolvimento do **HarukaMirai Dbg**, em meados de 2024, eu não fazia ideia do quão complexo seria encontrar um bom hardware para dar continuidade ao projeto. Talvez isso não faça muito sentido para você, caso não viva no Brasil, mas um simples hardware pode custar até 5x mais do que o valor normal, devido às taxas abusivas e à pseudo-proteção das indústrias locais — o que, na prática, impede a inovação, favorece a compra de produtos white-label e estimula a importação por zonas francas sem qualquer imposto. Enquanto isso, a população fica à mercê de um problema que deveria ser resolvido para gerar empregos e inovação.
**Anyway**, este artigo não é político. Eu odeio política — e como alguns aspectos do meu país natal funcionam — então vamos direto ao que importa e amamos.

Após muita pesquisa, consegui encontrar algumas alternativas:

Obter um **Raspberry Pi 5** e investir nos módulos necessários, gastando um absurdo por causa dos impostos e do dólar alto.

Comprar um **Samsung Galaxy Book Go** no mercado nacional — a única opção — usado.

Obviamente, minha preferência foi pelo **Samsung Galaxy Book Go**, que tinha um hardware mais eficiente. Contava com um processador **Snapdragon 7c** e o **Windows 11 ARM64** — exatamente tudo o que eu precisava. E adivinha? Ao olhar em uma plataforma de vendas de hardwares usados, comecei a negociar com o vendedor. Após alguns minutos de conversa, consegui convencê-lo a me vender por 1/3 do preço original. Uma vitória, considerando que ele havia comprado o aparelho com a esperança de jogar (!?), mas desistiu por conta da escassez de jogos compatíveis com ARM64 (e também porque, segundo ele, o layer de tradução não entregava um bom desempenho).

**Update:** durante a escrita deste artigo, o preço desse hardware dobrou.

Em agosto de 2024, finalmente iniciei o projeto com o hardware em mãos. Nessa época, eu já tinha definido que o nome do debugger seria uma alusão à música da banda japonesa **Kankaku Piero**, abertura de um dos meus animes favoritos: **Black Clover**. Também já havia decidido que utilizaria **Qt com C++**, pois seria a forma mais eficiente, estável e prática para dar suporte ao Windows ARM64 via build com MSVC. Minha aventura estava apenas começando.

Eu já tinha quase toda a engine de debug completa e havia resolvido muitos dos problemas relacionados às estruturas internas do sistema operacional, que eram diferentes (vamos ver isso em detalhes mais adiante neste artigo). Em outubro de 2024 — três meses após o início do projeto — comentei com um amigo de confiança, o **rem0obb**, sobre minha ideia. Na mesma época, ele estava iniciando sua própria empresa de tecnologia e me convidou para integrar a **Maldec Labs** como pesquisador, levando comigo o **HarukaMirai Dbg**, já que isso agregaria conhecimento para ambos os lados.

Após diversos meses de desenvolvimento contínuo, em dezembro de 2024, o projeto passou a ser tratado como um produto à parte, com o objetivo de gerar conhecimento e material para futuros produtos, como o **Decompiler**. Durante uma reunião de revisão, todos estavam muito empolgados com o HarukaMirai Dbg. Mas o nome não era tão marcante assim — precisávamos de algo com mais impacto. Uma reunião que deveria durar uma hora acabou tomando três, envolvendo todo o time da Maldec Labs na escolha do novo nome do projeto. Assim surgiu o **KoiDbg**, e junto dele, definimos uma ***deadline*** para o lançamento em janeiro de 2025.

Quando a data chegou, já tínhamos tudo pronto. Na madrugada de **11 para 12 de janeiro**, lançamos o projeto — mas sem o código-fonte, pois ainda queríamos extrair mais conhecimento antes da liberação.

Veja o vídeo de apresentação:

[![MalDec Labs presents： KoiDbg](https://img.youtube.com/vi/vCgGMcGksp8/0.jpg)](https://www.youtube.com/watch?v=vCgGMcGksp8)

Infelizmente, logo no mês seguinte, precisei me afastar do time de desenvolvimento e pesquisa do KoiDbg, passando a atuar apenas como **conselheiro, responsável por segurança e tester da Maldec Labs**. Isso aconteceu porque o projeto estava consumindo demais o meu tempo livre — e esse não era meu trabalho principal. Resultado: longas jornadas sem descanso. Péssima ideia, não é mesmo?

Na mesma época, meus amigos da Maldec já estavam focados em outros produtos da empresa e iniciando a transição para se tornar uma desenvolvedora de jogos. O **KoiDbg** deixou de ser suportado, e então decidimos, em conjunto, liberar o código-fonte do projeto. Junto com ele, também preparamos este artigo completo e detalhado sobre como funciona um debugger para Windows ARM64, os internals do sistema e toda a experiência vivida, servindo como guia para quem quiser usar o KoiDbg como base, criar seu próprio do zero, ou simplesmente aprender algo novo.

### Windows debuggers 101 - Qualquer arquitetura

![#1](/imgs/img01.png)

Antes de continuarmos com a parte técnica, você, caro leitor, consegue fazer um exercício de imaginar — ou até mesmo mentalizar — como um debugger, como o x64dbg, WinDbg ou IDA Server, funciona? Caso não, sem problemas. Vamos entender isso agora!

Um debugger nada mais é do que uma aplicação que recebe e trata eventos ```DEBUG_EVENT``` (que, basicamente, são exceções) gerados pela aplicação sendo depurada (debugee). Esses eventos são capturados pelo debugger, desde que ele tenha um ```HANDLE``` obtido via ```CreateProcess``` com a flag ```DEBUG_ONLY_THIS_PROCESS```, ou ao anexar-se a um processo já em execução utilizando a API ```DebugActiveProcess```.

No **KoiDbg**, ou em qualquer outro debugger, centralizamos essa captura em uma única rotina — bem conhecida por quem desenvolve esse tipo de ferramenta — chamada de **Debug Loop**. Essa rotina faz uma chamada para ```WaitForDebugEvent```, que retorna uma estrutura ```DEBUG_EVENT``` com o novo contexto da exceção. Nela, determinamos o tipo de evento a ser tratado pelo campo ```dwDebugEventCode```, implementando casos específicos para cada tipo de evento, sendo os mais comuns:

- EXCEPTION_DEBUG_EVENT
- CREATE_THREAD_DEBUG_EVENT
- CREATE_PROCESS_DEBUG_EVENT
- EXIT_THREAD_DEBUG_EVENT
- EXIT_PROCESS_DEBUG_EVENT
- LOAD_DLL_DEBUG_EVENT
- UNLOAD_DLL_DEBUG_EVENT
- OUTPUT_DEBUG_STRING_EVENT
- RIP_EVENT

Para cada um desses eventos, existe um campo específico dentro da estrutura ```DEBUG_EVENT```, conforme abaixo:

```c++
typedef struct _DEBUG_EVENT {
  DWORD dwDebugEventCode;
  DWORD dwProcessId;
  DWORD dwThreadId;
  union {
    EXCEPTION_DEBUG_INFO      Exception;
    CREATE_THREAD_DEBUG_INFO  CreateThread;
    CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
    EXIT_THREAD_DEBUG_INFO    ExitThread;
    EXIT_PROCESS_DEBUG_INFO   ExitProcess;
    LOAD_DLL_DEBUG_INFO       LoadDll;
    UNLOAD_DLL_DEBUG_INFO     UnloadDll;
    OUTPUT_DEBUG_STRING_INFO  DebugString;
    RIP_INFO                  RipInfo;
  } u;
} DEBUG_EVENT, *LPDEBUG_EVENT;
```

Para entender melhor o funcionamento, imagine que sua aplicação depurada tenha um breakpoint (seja ele de hardware ou software). Quando esse breakpoint for atingido, será gerado um evento com o código ```EXCEPTION_DEBUG_EVENT```, que deverá ser tratado pelas informações presentes na estrutura ```EXCEPTION_DEBUG_INFO```. É nessa estrutura que identificamos o tipo de breakpoint, permitindo que tomemos alguma decisão — seja remover o breakpoint ou apenas continuar a execução.

Toda vez que uma exceção de debug é capturada, você deve utilizar a API ```ContinueDebugEvent```, passando ```DBG_EXCEPTION_NOT_HANDLED``` para repetir a exceção enquanto nenhuma ação for tomada, ou ```DBG_CONTINUE``` para continuar após a ação ter sido executada — como no caso de um breakpoint que foi removido. **Falaremos mais sobre como breakpoints funcionam logo adiante.**

Apenas com a implementação dos handlers para cada uma dessas estruturas e eventos, temos o ciclo básico e o core de um debugger. No entanto, há muito mais envolvido, como stack, call stack, registradores, disassemblers e muito mais.

Alguns debuggers, como o **IDA Server** e o **WinDbg**, utilizam a interface [IDebugClient](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nn-dbgeng-idebugclient), que oferece diversas funcionalidades prontas para uso. Mas esse não é o caso de todos. Alguns, como o x64Dbg e o próprio **KoiDbg**, utilizam implementações próprias baseadas na estrutura do Debug Loop com as [APIs de debugging do sistema](https://learn.microsoft.com/en-us/windows/win32/debug/debugging-functions) — que será nosso principal foco a partir de agora, para compreendermos seu funcionamento.

### KoiDbg Internals

![#2](/imgs/img02.jpg)

Vamos abordar neste tópico o funcionamento interno do KoiDbg, iniciando desde o momento em que um processo é criado de maneira suspensa ou anexado. Explicaremos como lidamos com cada evento do DebugLoop, como processamos e organizamos cada informação para reutilização — como threads, módulos, memória, stack e outros — antes de entrarmos de cabeça em conceitos mais diretos relacionados à arquitetura ARM64.

Antes de mais nada, é importante ressaltar que, apesar de o KoiDbg ser um debugger exclusivo para ARM64, ele possui, sim, suporte ao Intel. Durante a etapa de desenvolvimento, nem todas as pessoas que trabalharam comigo no projeto tinham acesso a um processador ARM. Dessa forma, precisávamos de uma maneira para que elas pudessem testá-lo e contribuir com o desenvolvimento, trabalhando nas particularidades entre Intel e ARM64 posteriormente.

#### KoiDbg Init-DebugLoop

No KoiDbg, a interface gráfica do Qt é totalmente independente da lógica da engine, a qual, em sua maioria, é responsável apenas por exibir informações. Nosso foco inicia-se no fluxo de criação de um novo processo.

Quando um novo processo para debug é criado pela engine, o método ```DebuggerEngine::InitDebuggeeProcess``` é chamado. Sua lógica concentra-se unicamente em uma chamada para ```CreateProcessW```, com as flags ```DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE | CREATE_SUSPENDED```. Cada uma dessas flags garante aspectos importantes para a aplicação sendo debugada, que agregam informações relevantes para a análise. Um exemplo é o console output, **frequentemente utilizado por malwares** durante a fase de desenvolvimento, mas normalmente ocultado. Com essa flag, conseguimos capturar a saída do console caso o atacante esqueça de escondê-la. Além disso, a criação suspensa do processo nos garante a possibilidade de capturar todas as etapas da execução da aplicação, servindo como uma segunda camada de garantia.

Logo após a criação do processo, já a partir do construtor da classe da própria engine, temos a chamada para ```DebuggerEngine::DebugLoop```, que executa em uma nova thread separada da principal — onde a interface gráfica do Qt roda — para termos controle total sobre a sessão de debug sem interferir no desempenho da interface gráfica em nenhum momento.

Ao observar a implementação da lógica presente no ```DebuggerEngine::DebugLoop```, é possível perceber a similaridade com o conceito básico de um debugger, como apresentado anteriormente no tópico **Windows debuggers 101 - Qualquer arquitetura**:

![#3](/imgs/img03.png)

A única grande diferença aqui é a presença de determinados ***handlers*** que tratam cada um dos eventos recebidos de maneira separada, seguindo a lógica necessária para processá-los e agregar informações úteis a quem está realizando o debug. Vamos nos concentrar em compreender cada um deles.

###### handleExceptionDebugEvent

![#4](/imgs/img04.png)

Quando temos um evento do tipo **EXCEPTION_DEBUG_EVENT**, na maioria das vezes ele está associado a breakpoints de hardware ou software. No entanto, outras exceptions também podem ocasionar esse evento — a mais conhecida é a **EXCEPTION_ACCESS_VIOLATION**. Quando o KoiDbg recebe uma exception inesperada, ele sempre aguarda uma ação do usuário antes de retomar a execução do processo em debug, de forma semelhante a diversos outros debuggers do mercado. Uma lista com todas as exceptions possíveis desse evento pode ser encontrada na [página da MSDN](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record#members), e o KoiDbg é totalmente compatível com cada uma delas.

Assim que uma exception de debugging é recebida — independentemente de qual seja —, por padrão, o contexto antigo do debugger é descartado, e um novo é armazenado (contexto de atualização do debugger do Koi). Você deve se perguntar: o que seria um contexto? Cada debugger trata essa etapa de maneira diferente. No Koi, temos nosso próprio contexto da sessão de debug, onde, a cada novo evento, excluímos todo o contexto da stack e dos registradores desde a última exception, para atualizar tudo com base no TID da thread que gerou a exception. Esse é um ponto importante. Já parou para pensar como um debugger consegue gerenciar o contexto de cada thread? É através do TID. Cada thread possui seu próprio contexto a ser gerenciado. No Koi, essa atualização é feita pelo método ```DebuggerEngine::UpdateAllDebuggerContext```:

![#5](/imgs/img05.png)

Cada exception nos métodos ```ListAllHandleObjectsForDebugeeProcess``` e ```AnalyseDebugProcessVirtualMemory``` exige tratamentos mais complexos. Já os dois outros métodos, que recebem diretamente o TID como argumento, realizam a maior parte do trabalho de atualização da interface gráfica do usuário — e serão explicados em detalhes ainda neste artigo.

###### handleCreateThreadDebugEvent

Quando uma exception ```CREATE_THREAD_DEBUG_EVENT``` é recebida a partir do processo em debug, esse handler entra em ação para capturar informações básicas da thread criada, como o **HANDLE** com acesso total, **TID, Thread Basic Information, endereço base, endereço da TEB e Priority Level**. Todas essas informações são armazenadas em uma classe responsável por gerenciar o ciclo de vida e o estado de cada uma das threads da sessão de debug, chamada ```DebugThread```:

![#6](/imgs/img06.png)

! Se você estiver interessado na lógica utilizada para consultar a TBI (Thread Basic Information), verifique o tópico [KoiDbg Utils](#koidbg-utils).

###### handleCreateProcessDebugEvent

Sempre que um evento ```CREATE_PROCESS_DEBUG_EVENT``` é recebido, ele está associado à primeira thread do loader em execução, que será transferida para o código executável. Esse evento é disparado juntamente com o **LdrpDoDebuggerBreak**, o qual nos notifica que o processo e seu espaço de memória foram inicializados, nos dando a oportunidade de modificar o comportamento do processo antes que o código original comece, de fato, a ser executado.

Geralmente, esse evento vem seguido de um ```EXCEPTION_DEBUG_EVENT```. No caso do Koi, aproveitamos essa segunda oportunidade para atualizar os contextos do debugger e lidar com a interrupção junto com o usuário. No entanto, neste handling, utilizamos esse momento por outro motivo: esta é a única chance que temos de capturar a primeira thread (a principal de todas) da aplicação sendo depurada — juntamente, é claro, com o módulo do executável (para ser exibido na nossa lista de módulos carregados pelo processo).

**Como você estudou sobre o funcionamento do sistema operacional, sabe que um executável também é considerado um módulo dentro de um processo, assim como todos os outros.**

Veja a implementação:

![#7](/imgs/img07.png)

###### handleExitThreadDebugEvent

Este handler é sempre disparado quando um evento ```EXIT_THREAD_DEBUG_EVENT``` é recebido. A lógica aqui é totalmente autoexplicativa e previsível. Quando ocorre uma notificação de saída de thread, o Koi recupera, a partir do TID do evento, o objeto da thread correspondente na lista global de threads e o move para a lista global de threads passadas, para que o usuário possa ter um feedback de quais threads existiram, caso algum detalhe tenha passado despercebido durante a análise. Isso é muito importante, e nem todos os debuggers possuem essa funcionalidade.

###### handleExitProcessDebugEvent

Quando recebemos um evento ```EXIT_PROCESS_DEBUG_EVENT```, ele está sempre associado à thread principal da aplicação, cujo ciclo de vida foi encerrado. O Koi trata esse evento como uma oportunidade para resetar todo o contexto da sessão de debug e notificar o usuário de que a sessão foi encerrada, fornecendo o código de saída da thread e a call-stack mais recente armazenada, caso algo não tenha saído como planejado pelo usuário.

![#8](/imgs/img08.png)

###### handleLoadDllDebugEvent

Quando um evento ```LOAD_DLL_DEBUG_EVENT``` é recebido, o Koi armazena o handle do módulo carregado, obtém o nome da DLL a partir da handle table do processo sendo depurado e também o endereço base do módulo. Cada um dos módulos carregados é então armazenado em uma lista global de módulos, permitindo que o usuário tenha controle total sobre eles. Veja a implementação:

![#9](/imgs/img09.png)

**! Não se preocupe com cada detalhe desta parte/imagem, por exemplo: ```GetFileNameFromHandle``` e a classe da engine Kurumi serão abordados mais adiante no artigo.**

###### handleUnloadDllDebugEvent

Quando recebemos um evento ```UNLOAD_DLL_DEBUG_EVENT``` no Koi, ele está sempre relacionado ao descarregamento de algum módulo no processo de debug. Nesse caso, recuperamos esse módulo da lista global de módulos e o adicionamos à lista de módulos passados, para que o usuário tenha métricas e informações sobre os módulos descarregados, sem perder nenhum detalhe durante a análise. Veja a implementação:

![#10](/imgs/img10.png)

###### handleOutputDebugStringEvent

No caso do evento ```OUTPUT_DEBUG_STRING_EVENT```, não temos muitos segredos. Apenas capturamos a string que foi passada como parâmetro para a função da WinAPI [OutputDebugStringW](https://learn.microsoft.com/pt-br/windows/win32/api/debugapi/nf-debugapi-outputdebugstringw) para exibir na status bar do KoiDbg.

###### handleRipEvent

De maneira similar ao evento anterior, o ```RIP_EVENT``` também é um caso específico em que renderizamos a informação na status bar do KoiDbg. Esse evento é bem raro e, na maioria das vezes, ocorre quando, por algum motivo estranho, o processo falha e perdemos a capacidade de depuração dele.

#### KoiDbg Engine Functions

Vamos agora explorar algumas lógicas internas da engine do KoiDbg responsáveis por auxiliar a lógica principal de debug, como a handle table, análise de memória virtual, contexto de registradores, engine de disassembler, interrupções de hardware e software, steps (into, over, out), comandos de debug e engine de patch/assembler.

##### ListAllHandleObjectsForDebugeeProcess

Uma das features mais interessantes que um bom debug pode oferecer é a capacidade de recuperar todos os handles da handle table do processo debugado. No Koi, com toda certeza, esse recurso está presente — inclusive em uma visualização dedicada, com uma aba específica para que o usuário possa ver quais handles o processo em questão abriu, o tipo e se existe algum nome/path associado a eles:

![#11](/imgs/img11.png)

Essa feature funciona com base na **systemcall** ```NtQuerySystemInformation```, com a **SystemInformationClass** específica ```SystemHandleInformation```, que retorna a estrutura ```SYSTEM_HANDLE_INFORMATION```:

```c++
typedef struct _SYSTEM_HANDLE {

    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;

} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {

    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];

} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;
```
Com isso, obtemos informações sobre os handles de todos os processos no sistema operacional. Mas, por uma questão de contexto, olhamos apenas para os handles do nosso PID de debug. Isso é feito por meio do helper ```UtilsWindowsSyscall::GetDebuggerProcessHandleTable```:

![#12](/imgs/img12.png)

A rotina acima é chamada a partir da rotina presente na engine do Koi, responsável por notificar a interface de usuário sobre cada novo valor recebido pelo procedimento de checagem da handle table do processo em questão:

![#13](/imgs/img13.png)

Em muitos ataques, o atacante precisa obter handles para arquivos, mutexes, mecanismos de IPC e muito mais. A partir disso, conseguimos, com total sucesso, recuperar informações para uma análise eficiente do mesmo.

##### AnalyseDebugProcessVirtualMemory

Analisar a memória completa do processo debugado é uma feature essencial para qualquer debug. Com o Koi não é diferente: ele é capaz de enumerar todas as regiões de memória, recuperando endereço, tamanho, informações/arquivos mapeados, tipo, estado e, claro, a proteção/permissões da página. Essa feature está, inclusive, disponível em uma aba dedicada, na ```Memory View```:

![#14](/imgs/img14.png)

Esse recurso foi implementado diretamente na engine do Koi e sua base se apoia em consultas realizadas por meio da WinAPI ```VirtualQueryEx```, analisando as informações da estrutura ```MEMORY_BASIC_INFORMATION``` para todo o range de memória possível da aplicação — obviamente, inspecionando cada type, state e protection por meio de helpers e constantes muito bem definidas:

![#15](/imgs/img15.png)

Outras informações também são levadas em consideração, com lógicas específicas para identificarmos o ```KUSER_SHARED_DATA_ADDRESS``` em arquiteturas ARM64 e Intel. Além disso, também encontramos e mapeamos a ```HYPERVISOR_SHARED_DATA```. Cada endereçamento válido que contenha informações consistentes é associado a uma classe modelo ```DebugMemory```, que garante que cada região seja posteriormente **analisada para capturar qualquer mudança — como, por exemplo, uma região recém-alocada sem permissão de execução que, de repente, altera para uma permissão de execução.** Veja um exemplo da implementação dessa feature:

![#16](/imgs/img16.png)

##### updateRegistersContext

Como mencionado no tópico de [Debug Loop](#koidbg-init-debugloop), a atualização do contexto dos registradores é uma das principais funcionalidades que um depurador precisa oferecer ao receber um evento de debug e aguardar alguma decisão do usuário. Um exemplo disso é um evento de breakpoint, onde o programa em depuração é completamente pausado e o usuário precisa visualizar todo o contexto de execução das threads envolvidas.

Quando você, caro leitor, pensa no funcionamento disso, consegue imaginar o conceito de threads do Windows? Se direcionar um pouco a sua atenção, vai se lembrar que, anteriormente, no tópico específico para esses eventos, mencionamos que este procedimento era chamado com o TID (Thread ID) que gerou a exceção. Essa é a melhor abordagem, pois no Windows cada thread possui seu próprio contexto e, geralmente, quando uma exceção é recebida, essa é exatamente a informação que o usuário deseja acessar.

No Koi, essa visualização está diretamente acessível na ```Debug View```:

![#17](/imgs/img17.png)

No exemplo da screenshot acima, temos um evento do tipo ```EXCEPTION_DEBUG_EVENT``` gerado a partir da ```LdrpDoDebuggerBreak```, diretamente na thread principal, antes mesmo do processo de debug e de qualquer código associado a ele ser executado. Perceba que o Koi aguarda por um evento de interação por parte do usuário, e o processo debugado está em estado **pausado**. Vamos entender como a captura dessas informações é feita e organizada para serem exibidas no Koi.

A captura se inicia a partir do ID da thread, obtendo acesso total a ela por meio da WinAPI ```OpenThread``` com a flag ```THREAD_ALL_ACCESS```. A partir disso, caso o Koi esteja debugando um processo ARM64, utilizamos a API ```GetThreadContext```, fornecendo a nova estrutura de contexto específica para o processador ARM64, [ARM64_NT_CONTEXT](https://learn.microsoft.com/pt-br/windows/win32/api/winnt/ns-winnt-arm64_nt_context). Como se sabe, o Koi também tem suporte à arquitetura Intel, apesar de não ser seu foco, e, caso esteja sendo debugado um processo x86_64, a antiga estrutura [CONTEXT](https://learn.microsoft.com/pt-br/windows/win32/api/winnt/ns-winnt-context) é utilizada.

![#18](/imgs/img18.png)

Com as informações de cada struct, é criado um par representando nome da informação e seu valor, para serem renderizados no widget **Register-View** do Koi:

![#19](/imgs/img19.png)

Alguns casos mais específicos, como é o caso das flags **EFLAGS** ou **CPSR**, são tratados de forma especial, devido a cada bit representar uma informação. Nesse caso, também parseamos cada informação antes de renderizá-la na interface gráfica:

![#20](/imgs/img20.png)

Registradores mais específicos de multimídia, como os **AVX** ou **NEON**, são tratados de maneira separada. No caso do ARM64, os registradores NEON são representados pela estrutura [ARM64_NT_NEON128](https://github.com/wine-mirror/wine/blob/master/include/winnt.h#L1796), que não é documentada oficialmente. Por isso, utilizamos a estrutura documentada no projeto Wine, no header **wine-winnt.h**, para interpretar a lógica e renderizar na interface do Koi:

![#21](/imgs/img21.png)

Você, caro leitor, pode pensar que essa lógica de parseamento dos registradores de uma thread é simples. No entanto, está redondamente enganado. Imagine o trabalho de sincronização necessário para mantermos sempre atualizadas as informações de cada thread do processo debugado. Por isso, o gerenciamento do ciclo de vida dessas threads é essencial.

##### updateCallStackContext

Outra capacidade essencial que um debugger deve oferecer é a de atualizar o contexto da ***call stack***. Essa informação é fundamental e contém muitos dados valiosos, como o fluxo completo de chamadas até a função atual. No Koi, essa funcionalidade está disponível em uma aba dedicada, com o nome bem sugestivo de ```Call Stack```, onde são exibidos não apenas todo o fluxo da ***call stack*** até o procedimento atual, mas também a thread à qual ela pertence. Veja o funcionamento deste recurso:

![#22](/imgs/img22.png)

Vamos entender como essas informações são capturadas pela engine. Isso ocorre com base nos contextos previamente capturados dos registradores da thread, onde o IP, o Frame Pointer e o Stack Pointer — **(PC, FP, SP)** — são utilizados pela API ```StackWalk64``` para recuperar as informações em uma estrutura [STACKFRAME64](https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-stackframe64).

![#23](/imgs/img23.png)

Cada endereço da stack pode ser obtido utilizando o campo ```AddrPC.offset```. Esse offset é somado a uma base fornecida na configuração da estrutura da stack. Por padrão, a stack utiliza o modo de endereçamento Flat em todos os debuggers do mercado:

![#25](/imgs/img25.png)

Os nomes associados aos símbolos, quando disponíveis, são obtidos pela lambda ```GetSymbolName```, que utiliza a API ```SymFromAddr``` para recuperar o nome correspondente, se disponível:

![#24](/imgs/img24.png)

Além da ```Call Stack```, vamos abordar outro recurso: a visualização da ```Local Stack```, no tópico [updateStackContext](#updatestackcontext).

##### updateStackContext

A ```Local Stack``` é de suma importância para um debugger, pois é através dela que informações como o endereço de retorno, argumentos (extras) e variáveis locais da rotina analisada são obtidas. No Koi, essa feature está presente na aba ```Debug View```:

![#26](/imgs/img26.png)

Na ```Local Stack``` do Koi, obtemos cada endereço presente na stack, juntamente com os devidos símbolos associados a eles (caso estejam disponíveis), agregando muito mais informação para análise. **No entanto**, eu havia planejado outra feature, como a de identificar strings, que infelizmente não foi implementada. Consulte a [KoiDbg Future](#koidbg-future) para uma lista completa das features planejadas que não foram implementadas.

Vamos compreender como essas informações são coletadas e a lógica por trás da construção da ```Local Stack```. Similar às demais features, também é necessário um handle para a thread do processo de debug, com permissão ```THREAD_ALL_ACCESS```. O primeiro passo para renderizar a stack é obter o contexto da thread, com o intuito de acessar o Stack Pointer (RSP para Intel e SP para ARM64). A partir disso, iniciamos a lógica para montar nossa stack:

![#27](/imgs/img27.png)

A lógica para montar a stack é bem simples: para cada 8 bytes subtraídos (sendo este o **Addressing Mode Size**) ou somados ao **RSP**, até um total de **0xFFA** — valor especificado por mim como limite da stack, expressivo e provavelmente mais do que o necessário para uma boa análise. Para cada endereço entre ```RSP - 0xFFA``` e ```RSP + 0xFFA```, utilizamos a API ```ReadProcessMemory``` para obter o endereço real ao qual nossa stack se refere, recuperando, se disponível, o símbolo associado a esse endereço. Assim, criamos uma visualização completa de:
```Endereço na Stack -> Endereço Referido -> Símbolo associado```.
A lógica é muito simples, confira:

![#28](/imgs/img28.png)

Uma lógica relativamente simples, não é mesmo? Apesar disso, ela agrega muita informação e nos permite — tanto em **ARM64 quanto em Intel** — obter exatamente as mesmas informações sem complicações, bastando ajustar o endereço do devido registrador **"Rsp/Sp"**.

##### UpdateDisassemblerView

A lógica do ```Disassembler View``` do Koi é bem prática e está presente em todos os debuggers do mercado. Ela permite que o usuário analise a região onde determinado evento de debug ocorreu e é essencial. Esta feature está disponível na ```Debug View```:

![#29](/imgs/img29.png)

Essa funcionalidade trabalha com base no contexto de registradores da thread que gerou o evento de debug e que aguarda alguma decisão por parte do usuário na interface gráfica. Ela é separada entre a engine principal e a engine de disassembler, que utiliza o projeto [Capstone](https://www.capstone-engine.org/) como backend. Inicialmente, a partir da estrutura ```CONTEXT``` ou ```ARM64_NT_CONTEXT```, recuperamos o registrador Instruction/Program Pointer/Counter equivalente (RIP para Intel e PC para ARM64). Com o valor desses registradores, consultamos via API ```VirtualQueryEx``` a estrutura ```MEMORY_BASIC_INFORMATION```, que carrega os campos ```BaseAddress``` — o endereço de início do código executável válido dessa paginação de memória — e ```RegionSize```, que representa o tamanho da região de memória.
A ideia aqui é, além de encontrar o ponto exato onde o código executável se inicia, também descobrir o seu tamanho. Para isso, utilizamos uma fórmula matemática simples para encontrar exatamente o trecho a ser analisado:

![mathformula](/imgs/math_formula_because_github_latex_suck.png)

Sendo o fator ```R``` o tamanho da ```RegionSize```, o fator ```A``` o valor do Instruction/Program Pointer/Counter, e ```B``` o endereço base onde a região de código se inicia. O objetivo é obter o tamanho exato do código a ser disassemblado — ou seja, o trecho que de fato interessa ao usuário. Veja a implementação prática dessa lógica:

![#30](/imgs/img30.png)

Perceba também que inicializamos uma estrutura ```DisasmEngineConfig```, que é importantíssima, pois configura a nossa engine de disassembler. Com tudo devidamente preparado, é o momento de inicializar a engine de análise e disassembler do Koi. Isso é feito de forma diferente dependendo da arquitetura, já que damos suporte tanto ao Intel quanto ao ARM64. Usamos as funções ```RunCapstoneEngineAarch64``` e ```RunCapstoneEnginex86```. Veja a chamada:

![#31](/imgs/img31.png)

O intuito aqui não é focar na engine de disassembler e na análise de instruções — isso será tratado no tópico dedicado ao [Disassembler Engine](#disassembler-engine). Como um leve overview, essa engine é capaz de analisar cada instrução individualmente, recuperar símbolos para endereços e ativar syntax highlight no widget com base no tipo da instrução. Isso é feito por meio de uma linguagem de script semelhante à sintaxe de HTML, chamada **"harukageneric"**, que é interpretada pelo Qt para renderizar as cores que você visualiza no widget de disassembler.

##### SetInterrupting

A interrupção (aka breakpoint) é o básico para um bom debugger, porque, na maioria das vezes, ela é o principal ponto de interação do usuário (claro, existem outras técnicas como memória, VEH e afins). Mas o core de um bom debugger se baseia em breakpoints, para que o usuário tenha uma boa sessão de debug. No Koi, dois tipos de breakpoints são suportados: Hardware e Software. No entanto, **outros estavam planejados**, mas não foram implementados. Verifique [KoiDbg Future](#koidbg-future) para uma lista completa das features planejadas que não foram implementadas. No Koi, breakpoints são definidos pela ```Debug View``` ou ```Console View``` e gerenciados pela aba ```HWSFT Interrupt```:

![#32](/imgs/img32.png)

O conceito de breakpoint de software e hardware difere bastante quando comparamos como isso é feito na arquitetura Intel com a forma como é feito na arquitetura ARM64. E, caro leitor, tentarei ser o mais claro possível.

Vamos começar explicando como um breakpoint de hardware funciona em processadores Intel, levando em consideração o funcionamento e o gerenciamento de threads do Windows. Podemos definir no **máximo 4 breakpoints de hardware**, que são adicionados nos registradores ```DR0-DR3``` e ativados com base nas flags do ```DR7```, com uma simples operação OR entre o valor atual e o bit de representação. Por exemplo, supondo que venhamos a definir um breakpoint no registrador ```DR3```: após definirmos o endereço desejado no registrador, ativamos o bit correspondente com um OR entre o valor atual de ```DR7``` e ```0b10000```. Isso é feito na estrutura ```CONTEXT``` obtida a partir de um handle da thread. Vale lembrar que isso não é universal para todo o processo — apenas para a thread da qual temos o contexto atual. Após essa configuração, um evento de ```BREAKPOINT``` será lançado exatamente na localização definida:

![#33](/imgs/img33.png)

Já no ARM64, o conceito muda completamente — também considerando o gerenciamento de threads no Windows. No ARM64, temos um máximo de 8 breakpoints de hardware, definidos através dos registradores [```Bvr```(Breakpoint Value Registers)](https://developer.arm.com/documentation/ddi0338/g/debug/debug-registers/cp14-c64-c69--breakpoint-value-registers--bvr-) e [```Bcr```(Breakpoint Control Register)](https://developer.arm.com/documentation/ddi0211/k/Cegfgdih). Como de costume, não há documentação pública da Microsoft sobre isso — apenas da própria ARM. Para definir um breakpoint, devemos acessar os índices de **0 a 7** de ```Bvr```, definindo o endereço desejado, e, em seguida, no mesmo índice, configurar o registrador ```Bcr``` com as flags **BCR_BAS_ALL (0xF << 5) e BCR_E (0xF << 5)**. Isso garante que o breakpoint seja ativado e capturado como um evento de debug, tudo por meio da estrutura ```ARM64_NT_CONTEXT```:

![#34](/imgs/img34.png)

Independentemente do breakpoint de hardware definido no Koi, seja ele ARM64 ou Intel, após configurados, eles são representados pela classe ```DebugBreakpoint``` e armazenados em uma lista global de breakpoints para gerenciamento.

Agora vamos entender como os breakpoints de software funcionam e são definidos.

Começando com a arquitetura Intel — provavelmente mais familiar para quem já trabalhou com o Windows — um breakpoint de software funciona alterando um único byte da sequência de opcodes para [```0xCC(INT 3)```](https://www.felixcloutier.com/x86/intn:into:int3:int1), que gera uma trap capturada como evento de debug. O byte original é armazenado, para que possamos restaurá-lo e remover o breakpoint, retomando assim a execução normal da thread. Veja:

![#35](/imgs/img35.png)

No ARM64, o conceito é semelhante, embora com diferenças naturais da arquitetura. A instrução de breakpoint ```(0xD43E0000) BRK 0xF000``` ocupa 4 bytes — o tamanho padrão de uma instrução válida. Essa mesma instrução é usada pelo intrinsic [__debugbreak recomendado pela Microsoft](https://learn.microsoft.com/pt-br/cpp/intrinsics/debugbreak?view=msvc-170): "No ARM64, o __debugbreak intrínseco é compilado na instrução brk #0xF000.". Assim como no Intel, também armazenamos a sequência de 4 bytes para que o breakpoint possa ser removido e a execução continue normalmente:

![#36](/imgs/img36.png)

Além disso, assim como acontece com os breakpoints de hardware, os breakpoints de software também são representados pela classe ```DebugBreakpoint``` e armazenados na lista global de breakpoints para gerenciamento.

##### RemoveInterrupting

Como abordamos no tópico [SetInterrupting](#setinterrupting), todos os breakpoints do Koi são armazenados em uma classe modelo chamada ```DebugBreakpoint``` e mantidos em uma lista global de breakpoints. Quando um usuário remove esse breakpoint, seja pela ```Console View``` ou pelo ```HWSFT Interrupt```, clicando sobre o breakpoint, o objeto correspondente é removido da lista global e o procedimento de remoção é iniciado. A lógica é bastante simples.

Caso a **interrupção seja de software**, o opcode original da instrução é restaurado, já que a classe modelo DebugBreakpoint armazena o valor original de backup em seu campo ```m_ucOriginalOpcodes```. Com base em outro campo, ```m_szOriginalOpcodes```, que armazena o tamanho da instrução (sempre 1 byte para Intel e 4 bytes para ARM64), essa mesma lógica funciona para ambas as arquiteturas. A única diferença aqui é que o contexto da thread (```CONTEXT``` ou ```ARM64_NT_CONTEXT```) tem o instruction pointer subtraído em 1 (para Intel) ou 4 (para ARM64), de forma a fazer o handling da exceção retornando ao início da execução do opcode restaurado. Confira:

![#37](/imgs/img37.png)

Se você for um leitor atento, vai perceber outra flag sendo assumida pela engine do Koi:  ```DebuggerEngine::CurrentDebuggerRule::BKPT_CONTINUE ```. Ela é responsável por sinalizar que o debugger lidou com a exceção ou alguma ação, e deve restaurar a execução com a flag  ```DBG_CONTINUE ``` para a API  ```ContinueDebugEvent```.

Já no que diz respeito à lógica da **interrupção de hardware**, o funcionamento é um pouco diferente, como mencionado no tópico anterior.

No ARM64, com base na classe modelo ```DebugBreakpoint```, encontramos o índice correspondente no contexto do ```ARM64_NT_CONTEXT```, alterando os valores daquele índice em ```Bvr e Bcr``` para zero. Veja como é feito:

![#38](/imgs/img38.png)

E no Intel, removemos o valor do registrador ```Dr0-Dr3``` com base na posição que ele utiliza. E, claro, removemos a flag correspondente do registrador ```Dr7``` por meio de uma operação ```AND + NOT``` com a negação da flag, invertendo o bit a ser limpo. Veja:

![#39](/imgs/img39.png)

##### UpdateActualIPContext

Atualizar o ```Instruction Pointer``` é algo básico e muito útil quando o usuário deseja controlar onde determinada thread deve executar — seja retornando a uma localização específica ou até mesmo redirecionando a execução para uma nova região que, originalmente, não estava sob controle da thread. **Como por exemplo, no caso de debug de shellcode**.

No Koi, essa funcionalidade está disponível no ```Debug View``` (através do menu de interação com o botão direito) e, claro, também pelo ```Console View```. Veja:

![#40](/imgs/img40.png)

No ARM64, isso é feito com base na estrutura ```ARM64_NT_CONTEXT```, alterando o registrador **Pc** para o endereço com o qual o usuário interagiu na interface gráfica. Já no Intel, o mesmo processo é realizado usando a estrutura ```CONTEXT``` e o registrador **RIP**. Em ambos os casos, como esperado, a alteração afeta apenas o contexto da thread que gerou o evento de debug em questão.

##### stepInto

Uma feature chamada ```stepInto``` parece, à primeira vista, super complexa. Mas, na verdade, ela só parece mesmo, pois sua implementação é relativamente mais simples do que aparenta. No Koi, essa feature está disponível na ```Debug View``` e pode ser acessada pelo menu ```Debug Commands```, veja:

![#41](/imgs/img41.png)

A partir do contexto da thread — ```ARM64_NT_CONTEXT``` ou ```CONTEXT``` — o Koi recupera o valor do ```Instruction Pointer (seja Pc ou RIP)```. Com base nesse valor, o Koi utiliza a ```DisassemblerEngine```, em específico o procedimento ```RunCapstoneForSingleStepARM64```, para recuperar o valor imediato, o endereçamento ou o branch da instrução atual do Instruction Pointer. Esse valor será então definido como o novo Instruction Pointer.

Para isso, utilizamos a [Capstone Engine](https://www.capstone-engine.org/). Consulte [Disassembler Engine](#disassembler-engine) para um overview completo sobre a engine de disassembler. Veja o funcionamento:

![#42](/imgs/img42.png)

##### stepOver

Uma feature de ```StepOver``` nada mais é do que um simples evento de ```EXCEPTION_DEBUG_EVENT``` (neste caso, com o event code ```SingleStep```) para a próxima instrução a ser executada pelo processador. É algo muito simples, pois, por meio de um único bit ativado em um registrador de flags, esse break é efetuado. No Koi, essa feature foi implementada de maneira bastante intuitiva, através do menu ```Debug Commands``` ou do ```Console View```. Veja:

![#43](/imgs/img43.png)

Enquanto no Intel essa feature é gerenciada pelo EFLAGS, através do bit TF (Trap Flag), no ARM64 o single-step é controlado pelo registrador de debug [MDSCR_EL1](https://developer.arm.com/documentation/ddi0487/latest), especificamente pelo bit SS (bit 21) — também conhecido como [T-Bit](https://developer.arm.com/documentation/ddi0601/latest/AArch64-Registers/MDSCR-EL1--Monitor-Debug-System-Control-Register). **Não existe nenhuma menção pública relacionada a esse tipo de evento de single-step pela Microsoft em sua documentação**, mas a implementação é bastante simples. Confira:

![#44](/imgs/img44.png)

##### stepOut

Para finalizar as features de Step, a última a ser abordada é a ```Step Out```. Como o nome sugere, ela é responsável por encontrar a instrução ```ret``` mais próxima do Instruction Pointer atual. Isso é feito analisando toda a região em torno do Instruction Pointer até que alguma instrução de retorno seja encontrada. No Koi, essa feature está disponível através do menu ```Debug Commands``` ou da ```Console View```, confira:

![#45](/imgs/img45.png)

Com base nas estruturas ```CONTEXT``` ou ```ARM64_NT_CONTEXT```, a engine do Koi obtém o ```Instruction Pointer``` do registrador apropriado ```(Pc/RIP)``` e utiliza a API ```VirtualQueryEx``` para obter uma estrutura ```MEMORY_BASIC_INFORMATION``` com o único intuito de calcular o tamanho da região de código executável após o Instruction Pointer, a fim de iniciar o escaneamento pelo opcode de retorno utilizando a ```Disassembler Engine```. O cálculo em questão é simples: apenas uma subtração entre dois fatores, sendo a ```Allocation Base``` subtraída do ```Instruction Pointer```. Assim, obtemos o valor X (tamanho anterior da página executável), que deve ser desconsiderado e subtraído do ```size da página``` executável. Com base nesse novo tamanho, isolamos apenas o trecho de código executável realmente relevante, que será utilizado para extrair o endereço final de execução:

![#46](/imgs/img46.png)

O procedimento está implementado na engine de disassembler, que será detalhada melhor no [tópico sobre a disassembler engine](#disassembler-engine). As funções ```RunCapstoneForStepOutARM64``` ou ```RunCapstoneForStepOutx86``` são responsáveis, com base em um buffer de opcodes válidos, por encontrar a instrução de retorno mais próxima — que encerraria um fluxo de execução convencional, como ```ret``` ou ```retn``` — e retornar o endereço para que um breakpoint de software seja adicionado nesse ponto. Confira:

![#47](/imgs/img47.png)

##### DebugCommandProcessingLoop

Vamos agora falar da parte mais divertida, na minha opinião, que é a capacidade de manipular nossa sessão de debug com comandos no ```Console View``` do KoiDbg. A maioria dos debuggers oferece esse recurso, que é muito útil em uma análise rápida ou automatizada. No Koi, ela está localizada logo abaixo da aba ```Debug View```:

![#48](/imgs/img48.png)

O suporte do Koi é composto por múltiplos componentes, com um lexer próprio que interpreta os comandos e seus argumentos, adicionando-os a uma instância de lexer em uma variável global chamada ```m_commandProcessingQueue```. Essa fila utiliza uma implementação simples para o processamento de comandos em lote, através da classe ```SafeCommandQueue```, veja:

![#49](/imgs/img49.png)

Cada comando enviado a partir da interface do ```Console View``` é adicionado a um novo objeto ```Lexer```, responsável pelo parsing, e em seguida incluído na fila global ```m_commandProcessingQueue```, que é compartilhada pela engine entre a thread da interface e a thread de processamento de comandos (**DebugCommandProcessingLoop**) de maneira segura e sincronizada.

A thread de DebugCommand tem acesso total à engine, mas não à thread da sessão de debug, por motivos de segurança. No entanto, ela é capaz de acessar diversos recursos da sessão de debug por meio de wrappers seguros. Sempre que um comando é adicionado à fila, a thread o obtém e inicia o processamento, executando a ação desejada pelo usuário. Ao finalizar, remove o item da fila, sempre processando um comando por vez:

![#50](/imgs/img50.png)

Muitos comandos são suportados, entre eles:

| Comando | Funcionalidades |
|--|--|
| !mem index address | Visualiza determinado endereço no Hex View especificado pelo index. |
| !memclear index | Limpa a visualização do Hex View. |
| !memsave address size path | Salva um determinado buffer, a partir de um endereço e com um tamanho fornecido, no sistema de arquivos, de acordo com o path especificado. |
| !ko | Exibe informações de ajuda, documentações e suporte da engine. |
| !bs address | Define uma nova interrupção de software. |
| !bh address | Define uma nova interrupção de hardware. |
| !br address | Remove uma interrupção (de software ou hardware) definida no endereço fornecido. |
| !vw address | Visualiza o Disassembler View de uma região com base no endereço fornecido. |
| !imgbase | Obtém a image base do módulo principal do debugee. |

Muitos outros comandos de automação foram [imaginados para serem implementados](#koidbg-future); no entanto, ainda não foram desenvolvidos.

##### SetNewPatch

Um bom debugger precisa contar com uma funcionalidade para realizar patch, salvar e importar alterações. No Koi, isso foi implementado a partir da janela de contexto ao clicar sobre uma instrução no ```Disassembler View```, abrindo a ```Patch Code View```:

![#51](/imgs/img51.png)

O funcionamento dessa feature é bastante simples. Quando a interação ocorre no ```Disassembler View```, algumas informações — como o endereço da instrução — são passadas como argumento para o construtor da classe ```PatchCode```. A partir daí, a própria disassembler engine utiliza o procedimento ```RunCapstoneForSimpleOpcodeBlocARM64``` ou ```RunCapstoneForSimpleOpcodeBlocX86``` para desassemblar a instrução, exibindo-a em um campo de entrada para que o usuário possa iniciar sua edição.

![#52](/imgs/img52.png)

Quando o usuário finaliza o patch e clica no botão para aplicá-lo, o fluxo real do processo se inicia: a string modificada é convertida em código de máquina usando a ```Assembler Engine``` do Koi, que tem como backend o [Keystone](https://www.keystone-engine.org/). Essa engine será abordada em um [tópico futuro ainda neste artigo](#assembler-engine). Os procedimentos responsáveis por essa montagem são ```assembleArm64Code``` ou ```assembleX64Code```. O Koi também é capaz de identificar e validar automaticamente se houve algum erro durante o processo de assembly do patch, garantindo que tudo esteja correto antes de substituir os opcodes originais pelos novos. Confira:

![#53](/imgs/img53.png)

Após um patch bem-sucedido, todas as alterações são armazenadas em uma classe modelo chamada ```DebugCodePatchs``` e repassadas para a engine principal por meio de um callback, para que sejam gerenciadas durante todo o ciclo de vida da sessão de debug. Isso permite que o usuário exporte ou restaure os dados a qualquer momento — um recurso muito útil para quem analisa malware, participa de CTFs ou deseja apenas crackear um binário.

##### extractPdbFileFunctions

Algumas vezes, um engenheiro reverso pode dar muita sorte e encontrar um arquivo de símbolos (PDB), ou até mesmo um desenvolvedor curioso analisando uma aplicação de sua autoria (ou símbolos de algum binário de sistema). O fato é que esses arquivos carregam informações muito úteis e agregam bastante valor à análise. Pensando nisso, o Koi possui uma feature para parsing de arquivos PDB fornecidos pelo usuário, que são importados na sessão de debug para enriquecer as informações de análise. Veja:

![#54](/imgs/img54.png)

O funcionamento deste recurso é baseado em duas engines separadas: a ```Debug Engine```, responsável por notificar a [```Kurumi Eninge```](#kurumi-engine), que é quem trabalha diretamente com arquivos de símbolos, gerenciando operações como download, parseamento e importação na sessão de análise. O procedimento da ```Kurumi Engine``` utilizado para essa tarefa é o ```ParsePdbFunctionsAndSymbolsByPath```. Apenas o path é necessário como argumento, e ele retorna todo o mapa de símbolos e endereços presentes no arquivo para serem sincronizados posteriormente. Confira:

![#55](/imgs/img55.png)

A implementação da feature de parsing na ```Kurumi Engine``` também é bastante simplificada, utilizando apenas APIs fornecidas pela DbgHelper (tudo será detalhado no tópico referente a esta engine):

![#56](/imgs/img56.png)

#### Kurumi Engine

Kurumi Engine é um dos componentes mais importantes do Koi, pois ela é responsável por trabalhar com arquivos de símbolos, gerenciando, obtendo, parseando e adicionando-os na sessão de análise do debug. Ela é capaz de extrair qualquer informação de um símbolo, seja ele de sistema, obtido a partir da Microsoft, ou um arquivo fornecido pelo próprio usuário. Neste tópico, a minha ideia é explicar totalmente o seu funcionamento, focando na engenharia de sua lógica e nos pontos-chave.

##### Modularização

Diferente dos demais componentes do Koi que já conhecemos nos tópicos anteriores, a Kurumi Engine é um componente totalmente separado — ou seja, um arquivo lib independente que é integrado via linking e com um header de referência. Dessa forma, muitos wrappers para exports foram criados para facilitar a organização do projeto.

##### InitKurumiKOPDB

Este procedimento é um dos primeiros a serem executados na ```Kurumi Engine``` em um fluxo de sessão normal de debugging, sendo chamado pela própria engine de debug ao iniciar, com o intuito de obter os símbolos de módulos do sistema — sendo o principal deles a **ntdll.dll**. Esses metadados são salvos em um diretório chamado ```KoiDbgPdbs```, na raiz do Koi, seguindo o padrão do nome do módulo com a extensão ```.KOPDB```. Confira:

![#57](/imgs/img57.png)

##### DownloadKoiPdb

Quando um novo módulo de sistema está pronto para ser analisado pela ```Kurumi Engine```, é necessário obter o símbolo diretamente da msdl-cdn da Microsoft. Isso é feito de maneira muito simples, craftando a URL manualmente, extraindo o nome do módulo e seu GUID no processo.

No Koi, após craftar a URL para download do símbolo, utilizamos a WinAPI ```URLDownloadToFileW```, que atua de maneira síncrona para realizar o download do arquivo e salvá-lo em disco para posterior processamento:

![#58](/imgs/img58.png)

Destaco que utilizar a ```URLDownloadToFileW``` não é a melhor prática; no entanto, uma melhoria já havia sido planejada para o [futuro do koi](#koidbg-future). Para uma primeira versão, contudo, ela serviu maravilhosamente bem.

##### FindPdbField

A Kurumi Engine é capaz de obter o offset de um determinado símbolo de um arquivo PDB apenas com o nome. Isso é essencial para análises mais específicas, como a [Analise de Estruturas do Loader do Windows](#extracting-windows-loader-struct-information---koidbg). E tudo isso é feito utilizando as próprias APIs disponíveis no DbgHelp.

O funcionamento não é nada complexo: após inicializar com ```SymInitialize```, definir o search path dos símbolos com ```SymSetSearchPath``` e dar load no arquivo PDB com ```SymLoadModuleEx```, basta usar uma chamada para ```SymGetTypeFromName``` a fim de recuperar as informações referentes ao símbolo desejado em uma estrutura ```SYMBOL_INFO```:

```c++
typedef struct _SYMBOL_INFO {
  ULONG   SizeOfStruct;
  ULONG   TypeIndex;
  ULONG64 Reserved[2];
  ULONG   Index;
  ULONG   Size;
  ULONG64 ModBase;
  ULONG   Flags;
  ULONG64 Value;
  ULONG64 Address;
  ULONG   Register;
  ULONG   Scope;
  ULONG   Tag;
  ULONG   NameLen;
  ULONG   MaxNameLen;
  CHAR    Name[1];
} SYMBOL_INFO, *PSYMBOL_INFO;
```

A partir disso, é possível recuperar o campo ```Address```, que armazena o offset do procedimento em questão. Dessa forma, a ```Engine de Debug``` pode continuar a análise sem maiores problemas. Confira:

![#59](/imgs/img59.png)

##### FindPdbStructField

Outra feature muito utilizada pela engine do Koi, implementada pela Kurumi Engine, é a capacidade de extrair um field/parsear uma estrutura e seus fields (children) de um arquivo PDB. Isso é amplamente utilizado por diversos recursos de análise do Koi. Similar à feature [FindPdbField](#findpdbfield), esta funcionalidade está diretamente ligada à [Analise de Estruturas do Loader do Windows](#extracting-windows-loader-struct-information---koidbg). Sua implementação também se baseia em inicializar o ```SymInitialize```, definir um search path dos símbolos com ```SymSetSearchPath``` e carregar o arquivo PDB com ```SymLoadModuleEx```.

A principal diferença é que ela percorre os fields (children) utilizando ```SymGetTypeInfo``` com a flag ```TI_FINDCHILDREN``` a partir de um node principal, e com a flag ```TI_GET_SYMNAME``` para, com base no nome do field da estrutura, encontrar o offset correto informado pela engine de debugging. Apesar de essa feature parecer complexa, sua implementação é bem simples. Confira:

![#60](/imgs/img60.png)

##### ParsePdbFunctionsAndGetListInternal

Uma outra feature presente na ```Kurumi Engine``` é a capacidade de extrair todos os símbolos de funções declaradas em um arquivo PDB e obter um vector com todos os dados, tudo isso com base no path do módulo de sistema. Isso é feito de uma maneira muito simples e utilizando apenas APIs da **DbgHelp**. O processo começa com a inicialização pelo ```SymInitialize```, definição do search path para a pasta do KoiPdbs usando ```SymSetSearchPath```, carregamento do arquivo PDB com ```SymLoadModule64``` e, por fim, a enumeração de todos os símbolos para serem armazenados em um vector através da ```SymEnumSymbols```:

![#61](/imgs/img61.png)

A callback definida pela ```SymEnumSymbols``` tem o intuito de filtrar cada ```SYMBOL_INFO``` que possua a tag **SymTagFunction**, permitindo que sejam coletados e armazenados em um vector apenas o nome e o offset das funções declaradas no arquivo PDB, para uso posterior na engine de análise do Koi. Confira:

![#62](/imgs/img62.png)

#### KoiDbg Utils

Como mencionado em tópicos anteriores neste artigo, o Koi conta com alguns procedimentos utilitários que ajudam a agregar e obter determinadas informações, mas que não se encaixam em nenhuma categoria principal. O objetivo aqui é abordar como cada um desses procedimentos funciona e por que são importantes para o funcionamento da engine de depuração.

##### GetFileNameFromHandle

Quando você leu sobre o evento de [handleLoadDllDebugEvent](#handleloaddlldebugevent) , percebeu que, ao recebermos um evento relacionado ao carregamento de um módulo no processo debugee, a única informação que temos é o seu próprio handle. Esse procedimento é bastante útil por ser capaz de traduzir (ou, no termo mais preciso, mapear) esse handle para um diretório válido — ou seja, para o nome associado a ele —, permitindo assim recuperar o nome e o caminho de onde determinado módulo foi carregado.

A lógica para alcançar esse objetivo é relativamente simples. Se você estudou o básico da literatura do Windows Internals (7ª edição), sabe que o Windows mantém uma cópia de nomes e caminhos para certos tipos de handles, como é o caso dos handles de arquivos. Sendo assim, mesmo que esse handle não esteja diretamente associado à handle table do processo (e sem precisarmos cloná-lo para a nossa própria handle table), podemos criar um mapeamento usando a API [```CreateFileMapping```](https://learn.microsoft.com/pt-br/windows/win32/api/winbase/nf-winbase-createfilemappinga) para obter informações limitadas — que, por coincidência, incluem o nome e o caminho do arquivo.

Esse mapeamento é seguido, claro, pela projeção do arquivo na memória do processo do debugger com [```MapViewOfFile```](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile), finalizando com a obtenção do path usando o novo mapeamento com [```GetMappedFileNameA```](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmappedfilenamea). Confira a implementação:

![#63](/imgs/img63.png)

##### symbol_from_address

Quando estudamos o processo de parseamento da [stack local](#updatestackcontext) e da [call stack](#updatecallstackcontext), percebemos que esse procedimento é utilizado para recuperar o nome associado a um determinado endereço (símbolo) de maneira bastante eficaz, utilizando as APIs do DbgHelper. Esse processo faz uso de uma configuração específica da função [```SymSetOptions```](https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symsetoptions), aplicando as flags ```SYMOPT_DEFERRED_LOADS```, para carregar os símbolos conforme necessário pelo depurador, e ```SYMOPT_LOAD_LINES```, para ler os símbolos dos códigos-fonte, se disponíveis (de forma semelhante à extração de símbolos de código-fonte no WinDbg).

Isso garante que nenhum símbolo passe despercebido pelo Koi. Em seguida, basta inicializar com ```SymInitialize``` e chamar a API que, de forma quase mágica, faz todo o trabalho difícil de nos retornar a estrutura ```SYMBOL_INFO``` via [```SymFromAddr```](https://learn.microsoft.com/pt-br/windows/win32/api/dbghelp/nf-dbghelp-symfromaddr). Confira a implementação:

![#64](/imgs/img64.png)

##### GetDebuggerProcessHandleTable && GetRemoteHandleTableHandleInformation

Lidar com a tabela de handles é uma funcionalidade importantíssima para qualquer ferramenta de depuração. Essa funcionalidade foi inspirada em um recurso presente no projeto do debugger x64Dbg, embora o funcionamento seja bastante diferente em termos de implementação. Primeiramente, realiza-se uma consulta a todos os handles abertos no sistema utilizando a chamada de sistema [```NtQuerySystemInformation```](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation) com a flag ```SystemHandleInformation```. O objetivo aqui é obter a estrutura ```SYSTEM_HANDLE_INFORMATION```:

```c++
typedef struct _SYSTEM_HANDLE_INFORMATION {

	ULONG NumberOfHandles;
	SYSTEM_HANDLE Handles[ANYSIZE_ARRAY];

} SYSTEM_HANDLE_INFORMATION *PSYSTEM_HANDLE_INFORMATION;
```

Nesta estrutura, dois campos são muito importantes. O primeiro é a quantidade de handles que estão abertos no momento da consulta, determinado por ```NumberOfHandles```, seguido pela estrutura de array com o campo Handles, representado pela estrutura ```SYSTEM_HANDLE```, que é o alvo de nosso interesse:

```c++
typedef struct _SYSTEM_HANDLE {

    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;

} SYSTEM_HANDLE, *PSYSTEM_HANDLE;
```

Como essa funcionalidade utiliza recursos **não documentados**, a forma de identificar se um handle pertence ou não ao processo depurado é através do campo ```ProcessId```, comparando seu valor com o PID do próprio processo debugee, para todos os valores de handle presentes no sistema no momento da coleta. No Koi, armazenamos esses valores em um vetor, o que permite dar continuidade à segunda etapa da coleta de informações. Confira abaixo:

![#65](/imgs/img65.png)

Com os valores dos handles coletados, partimos para a segunda etapa: a coleta do máximo de informações relacionadas a eles. Como mencionado anteriormente no tópico [GetFileNameFromHandle](#getfilenamefromhandle), nem todos os objetos do sistema (handles) podem ter informações obtidas sem primeiro duplicá-los para um processo sob nosso controle. Nesse caso, do próprio debugee para o debugger (KoiDbg), o que é feito chamando a system call [```ZwDuplicateObject```](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwduplicateobject), obviamente, com um handle para o processo de depuração e a flag ```PROCESS_DUP_HANDLE``` devidamente especificada. Assim, podemos utilizar outras system calls para consultar mais informações sobre o handle, como [```ZwQueryObject```](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwqueryobject). Essas informações incluem a ```OBJECT_TYPE_INFORMATION``` e o ```ObjectName```. Confira a implementação:

![#66](/imgs/img66.png)

Por fim, essas informações são exibidas na aba ```Handles``` do Koi:

![#67](/imgs/img67.png)

Essas informações são bastante úteis durante uma análise. Imagine que você esteja analisando um artefato malicioso e ele crie um arquivo em disco, ou até mesmo abra um handle para outro processo com o intuito de realizar alguma injeção de código. Você será capaz de identificar isso e direcionar sua atenção de maneira mais eficaz.

#### Assembler Engine

A assembler engine do Koi é um componente necessário quando o usuário deseja criar um patch durante a sessão de debug. Para isso, a engine de Assembler utiliza um projeto estável como backend, neste caso o [KeyStone](https://www.keystone-engine.org/). O KeyStone permite que criemos abstrações específicas para nossa engine, focando apenas na lógica de validação do seu output com base em um código assembly escrito pelo usuário, para múltiplas plataformas, tanto Intel quanto ARM64. A ideia deste tópico é fornecer um overview completo de como essa abstração foi feita e como ela funciona.

##### assembleX64Code && assembleArm64Code

A implementação da abstração e do KeyStone não contém muitos segredos. A única diferença entre as arquiteturas (Intel ou ARM64) são as flags de inicialização do KeyStone: para Intel, utiliza-se a flag ```KS_ARCH_X86```, e para ARM64, a flag ```KS_ARCH_ARM64```. O fluxo de integração se resume a inicializar com ```ks_open``` e, em seguida, realizar a assemblagem utilizando a chamada ```ks_asm```, recuperando os novos opcodes que serão substituídos durante o processo de patch. O ponto principal aqui é a capacidade do Koi de gerenciar estados e erros desse processamento, a fim de informar o usuário sobre problemas no código escrito. Para isso, utilizamos um enum chamado ```ASSEMBLERENGINEERROR```, que retorna alguns possíveis estados. O primeiro deles é ```ERROR_KS```, que tem o objetivo de informar erros relacionados ao backend do KeyStone e sua configuração. O segundo, ```ERROR_CODE```, gerencia toda a parte relacionada ao processamento do código escrito pelo usuário e aos possíveis erros nele. Por fim, ```SUCCESS``` sinaliza que o processamento foi bem-sucedido e que um novo opcode está disponível para ser substituído. Confira a implementação:

![#68](/imgs/img68.png)

#### Disassembler Engine

Neste tópico, vamos abordar uma das principais e mais importantes capacidades que um debugger possui: a capacidade de disassemblar, adaptado para a lógica que ele deseja atingir. O Koi utiliza como backend o projeto [Capstone](https://www.capstone-engine.org/). Vamos explicar como a integração da ```Disassembler Engine``` do Koi foi estruturada nos mínimos detalhes, finalizando com uma explicação sobre a Haruka, a linguagem de marcação que o Koi utiliza para o processamento da syntax highlighting do ```Disassembler View```.

##### RunCapstoneEnginex86 && RunCapstoneEngineAarch64

O objetivo deste procedimento é o mesmo tanto para ARM64 quanto para Intel, mudando apenas as flags de configuração. Ele é responsável por gerenciar toda a lógica do ```Disassembler View```, tornando-o mais amigável e funcional, além de combinar outras features como a [Syntaxe-Highlight Haruka](#syntaxe-highlight-haruka), que será abordada mais adiante. De maneira geral, a ideia deste procedimento é identificar: branches, syscalls, referências diretas e indiretas, para processamento individual — além, é claro, de realizar o processamento de todos os opcodes presentes na página executável que foi extraída pela ```Debuger Engine```.

O funcionamento para obter o código disassemblado a partir dos opcodes extraídos da página pela debug engine é muito simples. Inicializamos com ```cs_open``` usando as flags de configuração na struct ```platform``` referentes a ARM ou Intel — respectivamente ```CS_ARCH_ARM64``` e ```CS_MODE_ARM``` — para em seguida fazermos a chamada para ```cs_disasm```, com o intuito de obter cada instrução, processando-as separadamente. Confira:

![#69](/imgs/img69.png)

A partir do processamento do disassembler, temos também o processamento das instruções para obter símbolos e highlight. Isso é feito com base em determinadas condições. Hoje, as lógicas verificadas são:

###### is_imm_or_branch

Verificamos todos os mnemônicos possíveis de controle de fluxo documentados no manual de referência do ARM (```b, bl, br, blr, cbz, cbnz, tbz, tbnz, b., bl., br., blr., cbz., cbnz., tbz., tbnz.```), e se o tipo do mnemônico é ```ARM64_OP_IMM``` (offset ou endereço). O intuito aqui é extrair o endereço e obter o símbolo associado a ele, veja:

![#70](/imgs/img70.png)

A implementação da lógica utiliza o procedimento já explicado anteriormente no tópico [symbol_from_address](#symbol_from_address), para que seja possível recuperar o símbolo como na imagem acima. Confira o detalhe desta implementação:

![#71](/imgs/img71.png)

###### is_mnem_syscalling

Verificamos os únicos dois mnemônicos responsáveis por operações de chamada de sistema (```svc e swi```), apenas com o intuito de definir uma marcação haruka para melhor identificá-los no ```Disassembler View```:

![#72](/imgs/img72.png)

###### is_imm_reference

Verificamos se um dos mnemônicos A ou B possui a flag ```ARM64_OP_IMM```, para que possamos definir uma marcação haruka que facilite sua identificação no ```Disassembler View```, permitindo ao usuário reconhecer facilmente seus usos:

![#73](/imgs/img73.png)

A lógica do ```Disassembler Engine``` aparenta ser simples, mas agrega muitas informações — tanto visuais quanto qualitativas — à sessão de debug, facilitando bastante a vida durante análises longas e complexas.

##### RunCapstoneForSingleStepARM64 && RunCapstoneForSingleStepx86

Como abordamos no tópico [stepInto](#stepinto), o objetivo desta implementação é encontrar o endereço de um desvio condicional indireto/direto, para extrair esse endereço e utilizá-lo na Engine, permitindo que seja definida uma interrupção de software logo no primeiro byte do endereço. A checagem é a mesma abordada em [is_imm_or_branch](#is_imm_or_branch). Confira a implementação:

![#74](/imgs/img74.png)

##### RunCapstoneForStepOutARM64 && RunCapstoneForStepOutx86

Similar à explicação abordada no tópico [stepOut](#stepout), o objetivo desta implementação é única e exclusivamente a capacidade de encontrar a instrução ```ret``` (retorno) mais próxima da região de código onde o Instruction Pointer está presente e retornar seu endereço. A engine fornece os opcodes da página executável e, a partir disso, a checagem e busca pela instrução ```ret``` é feita pelo verificador ```is_returning```. Confira a implementação:

![#75](/imgs/img75.png)

##### Syntaxe-Highlight Haruka

No Koi, utilizamos uma feature muito interessante para renderizar as cores (aka Highlight) no ```Disassembler View```, usando uma linguagem de marcação baseada em HTML que apelidamos de **Haruka**. Essa linguagem nada mais é do que um HTML com tags próprias, sendo elas:

| Tag de Marcação | Descrição |
|---|---|
| harukageneric | Utilizada para adicionar uma marcação de cor no texto de instruções disassembladas, normalmente em "vermelho". |
| harukabranch | Utilizada para adicionar uma marcação de cor no texto de instruções do tipo branch disassembladas, normalmente em "rosa". |
| harukasyscalling | Utilizada para adicionar uma cor em instruções do tipo syscall (chamadas de sistema), normalmente em "roxo". |
| harukacontrolflow | Utilizada para adicionar uma cor em instruções que tenham algum control flow (como call, jmp e afins — branch indireto sem comparação), normalmente na cor "dourado". |

Veja um exemplo de uso pela ```Disassembler Engine```:

![#76](/imgs/img76.png)

Por trás dos panos, toda a mágica da interpretação acontece no próprio widget do ```Disassembler View```, utilizando uma feature do ```Qt6``` chamada [QStyledItemDelegate](https://doc.qt.io/qt-6/qstyleditemdelegate.html). Sua implementação sobrescreve o método paint, permitindo que manipulemos como os elementos são desenhados. Nesse caso, conseguimos interpretar a string do ```Disassembler Engine``` como um HTML com CSS, fazendo com que toda a mágica aconteça automaticamente ao aplicar o CSS em cada uma das sintaxes do Haruka. Confira:

![#77](/imgs/img77.png)

Por fim, graças a esse processamento, obtemos um resultado que proporciona uma experiência excelente na sessão de debugging:

![#78](/imgs/img78.png)

#### Extracting Windows Loader Struct Information - KoiDbg

Neste tópico, vamos abordar a capacidade do Koi de recuperar algumas informações do loader do sistema que são muito úteis durante uma sessão de debugging. Como, por exemplo, possíveis VEH instaladas pelo debuggee, a verificação da existência de alguma técnica de [Nirvana Callback](https://github.com/keowu/InstrumentationCallbackToolKit) configurada no processo debuggee e, claro, a extração de todas as informações da NtDelegateTable. Todas essas informações estão disponíveis na aba ```Process Container Callbacks``` do KoiDbg. Confira:

![#79](/imgs/img79.png)

##### extractLdrpVectorHandlerListInformation

Esta feature funciona com base na estrutura ```ntdll!LdrpVectorHandlerList```, que nada mais é do que a lista responsável por armazenar os endereços das rotinas VEH registradas por meio da API [```AddVectoredExceptionHandler```](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler). Se você é familiarizado com o conceito de listas duplamente encadeadas no Windows, utilizando ```flink e blink```, esta lista funciona exatamente da mesma forma — com a diferença de que não é documentada (e os offsets em ```ARM64``` e ```Intel64``` diferem das versões ```ARM32``` ou ```Intel86```).

A estrutura da ```VectorHandlerList``` é composta por uma estrutura base e uma subestrutura, respectivamente: ```_VEH_HANDLER_ENTRY``` e ```_VECTORED_HANDLER_LIST```. Veja as declarações:

```c++
typedef struct _VEH_HANDLER_ENTRY {
    LIST_ENTRY  Entry;
    PVOID   SyncRefs;
    PVOID Idk;
    PVOID VectoredHandler;
} VEH_HANDLER_ENTRY, * PVEH_HANDLER_ENTRY;

typedef struct _VECTORED_HANDLER_LIST {
    PVOID              MutexException;
    VEH_HANDLER_ENTRY* FirstExceptionHandler;
    VEH_HANDLER_ENTRY* LastExceptionHandler;
    PVOID              MutexContinue;
    VEH_HANDLER_ENTRY* FirstContinueHandler;
    VEH_HANDLER_ENTRY* LastContinueHandler;
} VECTORED_HANDLER_LIST, * PVECTORED_HANDLER_LIST;
```

Durante a etapa de pesquisa do Koi, constatamos que a principal diferença dessa estrutura ocorre apenas em versões de endereçamento menor (4 bytes ou 32 bits do Windows). Sendo assim, a mesma estrutura e offsets podem ser compartilhados e utilizados entre Windows x64 e Windows ARM64 sem maiores problemas.

A implementação desta feature é relativamente simples e totalmente dinâmica, graças à ```Kurumi Engine``` — tudo feito de forma dinâmica, o que se tornou um grande diferencial do Koi até aqui. Primeiro, recuperamos o endereço de ```LdrpVectorHandlerList``` usando a [Kurumi Engine](#kurumi-engine), por meio do procedimento [FindFieldKoiPDB](#findpdbfield), confira:

![#80](/imgs/img80.png)

Após esta etapa inicial, utilizamos o helper ```UtilsWindowsSyscall::VEHList::GetVehList``` para obter um vetor com o endereço criptografado e descriptografado da VEH registrada pelo processo em debug. Isso é feito usando a API ```ReadProcessMemory``` para ler o endereço da ```LdrpVectorHandlerList```, armazenando a respectiva informação em uma estrutura ```VECTORED_HANDLER_LIST```. A partir do campo ```FirstExceptionHandler```, obtemos a primeira ```VEH_HANDLER_ENTRY``` para então iniciar o processo de varredura da lista via ```flink```, confira:

![#81](/imgs/img81.png)

A partir do momento em que obtemos a primeira entrada, iniciamos o processo de iteração via ```flink``` com o intuito de obter o campo ```VectoredHandler``` da estrutura ```VEH_HANDLER_ENTRY```. No entanto, isso não é tão simples quanto parece. Não podemos simplesmente usar o valor diretamente, pois ele está codificado por um ```cookie``` — um valor de 4 bytes gerado por [RtlEncodePointer](https://doxygen.reactos.org/d3/d4d/sdk_2lib_2rtl_2process_8c.html#ad52c0f8f48ce65475a02a5c334b3e959).

Portanto, é necessário implementar uma lógica para decodificar esse valor. Isso pode ser feito com uma chamada a ```RtlDecodePointer``` usando o handle de debug do processo. Mas isso por si só não é suficiente — é necessário implementar manualmente o algoritmo de decodificação do cookie.  **Isso é necessário porque não temos acesso ao DecodePointer do processo em debug (existe a possibilidade de usar a ```RtlDecodeRemotePointer```, porém, durante meus testes, ela não funcionou como esperado no Windows ARM64)**. O cálculo para o decode pode ser obtido revertendo a ntdll, como mostrado abaixo:

![#82](/imgs/img82.png)

A lógica de decodificação do cookie se mantém a mesma entre diferentes versões do sistema operacional dentro da mesma arquitetura. No entanto, entre arquiteturas diferentes, as constantes utilizadas no algoritmo também diferem. Por exemplo, na imagem acima temos o algoritmo usado no Windows x64, que não é o mesmo para Windows ARM64. Ainda assim, ele é suficiente para decodificar qualquer versão do Windows x64. Sendo assim, mantemos duas regras de decode distintas: uma para ARM64 e outra para Intel.

Felizmente, temos uma excelente solução para a decodificação do cookie de proteção, confira:

![#83](/imgs/img83.png)

Com esse problema resolvido, conseguimos enfim obter o endereço real da VEH registrada no processo em debug, armazená-lo em nosso vetor e avançar para a próxima entrada utilizando ```flink``` e a API ```ReadProcessMemory``` para coletar todas as informações necessárias para que nossa feature funcione corretamente, confira:

![#84](/imgs/img84.png)

##### extractNirvanaCallbackPresentOnDebugeeProcess

Esta feature nos permite analisar se uma [Nirvana Callback](https://github.com/keowu/InstrumentationCallbackToolKit) foi definida para alguma das threads do nosso processo debugee. Caso seja detectada, informamos ao usuário para agregar essa informação à sua sessão de debug.

Essa técnica funciona analisando os fields ```InstrumentationCallbackPreviousPc```, ```InstrumentationCallbackPreviousSp``` e ```Instrumentation``` do TEB (Thread Environment Block) de cada thread. Esses fields são extraídos por meio da [Kurumi Engine](#kurumi-engine), e então é feita uma chamada para ```UtilsWindowsSyscall::NtAndProcessCallbacks::detectNirvanaCallback```. Confira a implementação:

![#85](/imgs/img85.png)

Na prática, a implementação deste recurso é bastante simples: utilizamos a ```ZwNtQueryInformationThread``` com a flag ```ThreadBasicInformation``` para obter a estrutura ```THREAD_BASIC_INFORMATION``` e extrair o TebBaseAddress. A partir disso, somamos os offsets extraídos pela ```Kurumi Engine``` e lemos os valores via ```ReadProcessMemory```, checando o conteúdo de cada entrada. Caso alguma entrada esteja sendo usada (quando não deveria), temos uma nirvana detectada com sucesso. Veja o exemplo:

![#86](/imgs/img86.png)

Obviamente, essa técnica possui uma pequena limitação — a única, até então — que é não recuperar o endereço da callback definida pelo debugee. Apenas conseguimos detectar sua existência. No entanto, isso pode ser aprimorado em um futuro próximo.

##### extractNtDelegateTableCallbacks

Esta feature tem a capacidade de extrair todas as callbacks da Delegated NtDll, juntamente da WoW64 Table, para prover informações ao usuário durante a sessão de análise. Geralmente, essas callbacks são muito utilizadas por atacantes tentando evitar detecção ou até mesmo por mecanismos de segurança — seja para coleta de insumos ou para implementar técnicas de proteção no próprio executável. No Koi, elas são monitoradas para que, caso algo saia do padrão esperado, seja devidamente capturado durante a sessão de debugging.

**Não será abordado por completo o funcionamento de todas as técnicas de coleta, nem como as estruturas foram adaptadas e revertidas — apenas o funcionamento geral. Consulte o código-fonte do Koi para maiores detalhes sobre as estruturas.**

As seguintes callbacks são monitoradas:

| Name |  |
|--|--|
| LdrInitializeThunk |  |
| RtlUserThreadStart |  |
| RtlDispatchAPC |  |
| KiUserExceptionDispatcher |  |
| KiUserCallbackDispatcherHandler |  |
| KiUserApcDispatcher |  |
| KiUserCallbackDispatcher |  |
| KiRaiseUserExceptionDispatcher |  |
| LdrSystemDllInitBlock |  |
| LdrpChildNtdll |  |
| LdrParentInterlockedPopEntrySList |  |
| LdrParentRtlInitializeNtUserPfn |  |
| LdrParentRtlResetNtUserPfn |  |
| LdrParentRtlRetrieveNtUserPfn |  |
| RtlpWow64SuspendLocalProcess |  |
| LdrpInitialize |  |
| RtlAddVectoredExceptionHandler |  |
| RtlpDynamicFunctionTable |  |
| LdrpDllNotificationList |  |
| RtlpSecMemListHead |  |
| KernelCallbackTable |  |

###### Simple fields

Tirando a lógica das tabelas e listas (```RtlpDynamicFunctionTable```, ```LdrpDllNotificationList```, ```RtlpSecMemListHead``` e ```KernelCallbackTable```), a checagem é muito simples e feita com base na própria [Kurumi Engine](#kurumi-engine), que recupera o endereço e o nome associado e notifica a interface do usuário. Confira:

![#87](/imgs/img87.png)

###### RtlpDynamicFunctionTable

Já a lógica para o parseamento da tabela ```RtlpDynamicFunctionTable``` baseia-se em uma lógica própria, responsável por obter o endereço da tabela utilizando a [Kurumi Engine](#kurumi-engine), extraindo os dados do debuggee com o helper ```UtilsWindowsSyscall::DynamicFunctionTableList::GetDynFunctTableList``` e coletando as entradas caso uma callback tenha sido instalada, a fim de notificar a interface do usuário. Confira como o processo de ```Flink``` é feito nesta implementação:

![#88](/imgs/img88.png)

###### LdrpDllNotificationList

A lógica para o parseamento da ```LdrpDllNotificationList``` também é muito simples. A [Kurumi Engine](#kurumi-engine) obtém o endereço associado, e os dados do debuggee são extraídos com o helper ```UtilsWindowsSyscall::DLLNotificationsList::GetDllNotificationList```, onde a implementação realiza o Flink entre os dados para a extração de informações. Confira:

![#89](/imgs/img89.png)


###### RtlpSecMemListHead

Similar ao que vimos anteriormente, a implementação da lógica para ```RtlpSecMemListHead``` também utiliza a [Kurumi Engine](#kurumi-engine) para obter o endereço, e um helper dedicado, ```UtilsWindowsSyscall::SecMemListHead::GetSecMemListHead```, responsável por fazer o Flink entre os dados para extração. Confira:

![#90](/imgs/img90.png)

###### KernelCallbackTable

Para finalizar o nosso parsing de callbacks do Koi, temos a implementação para extração e análise da ```KCT Table```. O offset do procedimento é extraído utilizando a [Kurumi Engine](#kurumi-engine) e é parseado pelo helper ```UtilsWindowsSyscall::KernelKCT::GetKctTable```, que será responsável por obter a PEB do processo debuggee e ler o campo da KCT com o offset extraído, armazenando cada endereço presente no padrão chave-valor, com o nome e o endereço do procedimento. Confira (omitimos um pouco na screenshot porque a tabela possui muitos itens):

![#91](/imgs/img91.png)

##### Decompiler engine

Inicialmente, tínhamos planejado e implementado um decompiler para o Koi, presente na aba ```Decompiler View```. Esta feature utilizava como backend o projeto [llama.cpp](https://github.com/ggml-org/llama.cpp) e uma versão modificada do modelo [LLM4Decompile](https://huggingface.co/LLM4Binary/llm4decompile-6.7b-v1.5), com maior performance. Tudo era feito através de uma integração com API e um servidor na nuvem para processamento, onde apenas o código da ```Assembly View``` e os metadados de símbolos eram enviados para processamento, recebendo o resultado para exibição. No entanto, este projeto fazia parte de outro produto da Maldec Labs, impossibilitando a publicação.

## Analisando um Packer para ARM64, revertendo e debugando com o KoiDbg

Neste tópico, vamos escrever um packer simples, com um binário que utiliza a PEB e um shellcode responsável apenas por inicializar o ```calc.exe```. Tudo isso como exemplo de uso da PEB no Windows ARM64. O objetivo é apenas demonstrar a experiência de análise e engenharia reversa utilizando o KoiDbg.

##### Explorando a PEB no Windows ARM64 para escrever um loader

Quando nos referimos a um loader/packer usando um shellcode, normalmente lembramos da PEB (Process Environment Block). Ela é requisito obrigatório para que possamos escrever um shellcode dinâmico no Windows. No entanto, alguns pequenos detalhes diferenciam a PEB nas versões Intel e ARM64. Vamos entender quais são essas diferenças e escrever um simples shellcode, simulando a inicialização de um processo como um packer multiestágios.

A principal diferença entre o ARM64 e o Intel está na maneira de acesso à PEB (Process Environment Block). Enquanto no Intel utilizamos ```gs:[60h]``` para ```x86_64``` e ```fs:[30h]``` para ```x86```, no ```ARM64``` utilizamos o ```registrador x18```.

No ARM64, o valor do registrador é acessível via código facilmente utilizando uma intrínseca ```__getReg(18)```, com a grande diferença de que, primeiro, recuperamos o endereço da ```TEB (Thread Environment Block)``` e, a partir dela, acessamos o offset ```0x60 (ProcessEnvironmentBlock)``` da estrutura, para então recuperar a PEB (Process Environment Block). Para conhecer totalmente as intrínsecas do ARM64, recomendo a leitura de ["Intrínsecos do ARM64"](https://learn.microsoft.com/pt-br/cpp/intrinsics/arm64-intrinsics?view=msvc-170#A). Confira como a lógica para obter a PEB foi implementada:

![#92](/imgs/img92.png)

Na maioria das vezes, poucas diferenças são perceptíveis em relação às estruturas padrões do sistema operacional e, claro, não tão relevantes para o propósito no qual precisamos delas. Em geral, você pode obter as estruturas mais atualizadas por meio do site do [Vergilius Project](https://www.vergiliusproject.com/) ou até mesmo através do [PDBRipper](https://github.com/horsicq/PDBRipper). Neste artigo, utilizaremos estruturas sem nenhuma modificação quando as comparamos entre Intel e ARM64, como ```_PEB_LDR_DATA``` e ```_LIST_ENTRY```.

Com base nas explanações acima, desenvolvi um simples código em um processo que usa a PEB no Windows ARM64 para executar um shellcode e, a partir dele, inicializar o ```calc.exe```. Vamos analisar a implementação desse código antes de mergulharmos a fundo para entendê-lo através do Koi:

###### Loader

A primeira etapa desenvolvida para o nosso teste foi um simples loader que, utilizando nossa implementação da PEB para ARM64, aloca memória com permissão de execução, copia, adiciona o offset do entrypoint e cria uma thread.

![#93](/imgs/img93.png)

Este é um exemplo de loader bem simples, mas a ideia é justamente essa: fazer um teste para que possamos analisar como o KoiDbg se comporta durante uma análise.

###### Shellcode

A segunda etapa desenvolvida também utiliza a PEB, mas desta vez em um shellcode executado pela thread criada pelo Loader. O objetivo é encontrar a ```Kernel32``` para chamar a ```LoadLibraryA```, carregar a ```shell32.dll``` e, então, chamar a ```ShellExecuteA``` para abrir a ```calc.exe```.

![#94](/imgs/img94.png)

Como sempre, o velho ```calc.exe```:

![#95](/imgs/img95.png)

###### PEB

Sobre a implementação da PEB, veja como ela ficou:

![#96](/imgs/img96.png)

Bem simples. No método ```module_from_peb```, olhamos para a ```LDR_DATA_TABLE``` para encontrar o módulo recebido como argumento e obtermos sua base. Já no método ```GetFunctionAddressByName```, percorremos o diretório de exportação para encontrar o offset do procedimento que desejamos executar, simulando uma chamada para o ```GetProcAddress```.

Por fim, caso você tenha interesse em testar este simples código, **encontre-o no código fonte do KoiDbg**.

Veja o resultado, antes de continuarmos para a etapa de análise:

![#97](/imgs/img97.gif)

##### Analisando nosso código com o KoiDbg

Vamos agora analisar nosso binário de testes utilizando o KoiDbg.

![#98](/imgs/img98.gif)

Primeiramente, vamos iniciar uma nova sessão de debug para o arquivo ```loader.exe``` a partir do menu ```KoiDbg -> Open Executable```:

![#99](/imgs/img99.png)

Neste momento, nossa sessão está parada na ```LdrDoDebugBreak```. Vamos aproveitar essa oportunidade para carregar o arquivo de símbolos (PDB) através da aba ```Pdb Inspector```, no botão "Load PDB", e já definir um breakpoint na nossa main (para não precisarmos ficar procurando através da CRT Runtime):

![#100](/imgs/img100.png)

A partir disso, vamos deixar a sessão de debug rodar até que ela atinja o breakpoint que definimos:

![#101](/imgs/img101.png)

Agora, vamos encontrar a ```branch``` para o ```VirtualAlloc``` e definir uma interrupção de hardware sobre seu endereço, para que possamos obter o retorno do endereço alocado em ```x0```, além, é claro, de armazenar o tamanho da página alocada pela instrução ```mov x1, 0x801```:

![#102](/imgs/img102.png)

Perceba na imagem acima que o Koi conseguiu recuperar os nomes dos símbolos associados ao procedimento responsável por recuperar o procedimento a partir dos exports da ```kernel32```. Vamos agora deixar a sessão de debug continuar e atingir nossa interrupção para que possamos recuperar o endereço alocado:

![#103](/imgs/img103.png)

Vamos visualizar a região de memória alocada com o seguinte comando na ```Console View``` do Koi:

```
!mem 0x000001D536540000 0
```

O comando acima vai renderizar no primeiro ```HexView``` (índice 0) o endereço indicado. Veja o resultado:

![#104](/imgs/img104.png)

Vamos avançar um pouco mais e encontrar onde nossa thread é criada, definindo um breakpoint antes dela, para que possamos, enfim, capturar o shellcode completo:

![#105](/imgs/img105.png)

Agora, vamos rodar novamente o comando ```!mem``` no ```Console View``` do Koi para visualizarmos o shellcode:

![#106](/imgs/img106.png)

Por fim, vamos usar o comando ```!memsave``` para salvar o shellcode em disco:

```
!memsave 0x000001D536540000 0x801 C:\Users\joaov\OneDrive\Documents\DUMPS\sc.bin
```

![#107](/imgs/img107.png)

Vamos visualizar nosso arquivo de saída:

![#108](/imgs/img108.png)

##### Shellcode Adventure

**Leitor se pergunta: Ué, espera... e o Shellcode? O KoiDbg não suporta debugar ele? Afinal, é uma thread de qualquer forma.**

![#109](/imgs/img109.jpg)

Não vou debugar totalmente o shellcode do loader que desenvolvemos, mas vou demonstrar que sim, o KoiDbg é plenamente capaz de analisá-lo. Inclusive, nossa sessão de debug já tem tudo que é necessário para isso acontecer. Só precisamos entender um pouco mais sobre como a sessão de debug funciona.

A visualização que vemos agora representa a thread principal do KoiDbg, especificamente no nosso último breakpoint, antes de salvarmos o dump do shellcode via ```Console View```. O que precisamos fazer é:

1. Saber o exato endereço em que o shellcode começará.
2. Atualizar a ```Disassembler View``` do Koi para o novo endereço.
3. Adicionar um breakpoint de software e deixar o Koi capturar a nova thread, permitindo que a depuração ocorra.

Simples, não é mesmo? Vamos fazer isso.

Primeiramente, já temos o endereço de onde o shellcode começará. Ele é carregado pelo registrador ```x2``` ao chamar a ```CreateThread```, no mesmo ponto em que definimos o último breakpoint. Devemos obter esse endereço:

![#110](/imgs/img110.png)

Neste caso, o endereço que precisamos é ```0x00000190D8C40458```. Agora, vamos atualizar a ```Disassembler View``` do Koi com o seguinte comando:

```
!vw 0x00000190D8C40458
```

![#111](/imgs/img111.png)

Pronto, já podemos visualizar o código do nosso shellcode. Vamos definir uma interrupção e deixar que ela seja atingida, para que o Koi consiga capturar a execução da thread:

![#112](/imgs/img112.png)

Agora, vamos deixar que o debugger retome a sessão (```Debug Commands -> Run```) e quebre a execução da thread do shellcode logo no início:

![#113](/imgs/img113.png)

Então, a resposta à pergunta acima é: sim, o KoiDbg é plenamente capaz de debugar shellcodes e malwares multilayer!

## KoiDbg Future

Muitos planos futuros foram traçados para o KoiDbg antes que eu, pessoalmente, Keowu, decidisse encerrar o seu desenvolvimento. Neste tópico, minha ideia é que exploremos cada uma das features que estavam previstas para ele.

###### Emulação

Uma das funcionalidades que planejávamos trazer para o Koidbg era a capacidade de emulação. Esse recurso já estava em testes e não foi implementado porque o suporte à compilação precisava ser ajustado, e isso não era prioridade no momento. O backend para emulação seria fornecido pelo projeto [Unicorn Engine](https://www.unicorn-engine.org/). Alguns arquivos de testes dessa funcionalidade estão presentes no código de testes do KoiDbg, chamado ```TestesUnicornIntegration.hh```. Confira a implementação do teste:

![#114](/imgs/img114.png)

###### Recuperar Strings para visualização na Local Stack View

Outro recurso que tínhamos planejado para o Koi envolvia uma funcionalidade especial para a [Local Stack View](#updatestackcontext), que seria a capacidade de analisar se um endereço dentro da stack possuía uma string ASCII ou Unicode válida, permitindo que o usuário visualizasse a string sem precisar utilizar o ```Hex View``` do Koi.

###### Graph View

Um recurso muito útil para um debugger, a visualização de grafos para o disassembler, também foi planejado, e até mesmo um código de testes foi feito. No Koi, utilizaríamos a [linguagem Dot](https://graphviz.org/doc/info/lang.html) e planejávamos usar o projeto Chromium Embedded para renderizar a biblioteca Javascript, o que seria mais fácil do que tentar portar um interpretador baseado nas APIs do Qt. O código de testes está disponível no arquivo ```TestesChromiumEmbeddedIntegration.hh```. Confira:

![#115](/imgs/img115.png)

###### Suporte a Scripts e Automação via Lua

Atualmente, o Koi possui, de certa forma, suporte a scripts, mas não como automação. Ele apenas aceita comandos, como os que vimos ao longo do artigo, sendo utilizados no ```Console View```. Uma ideia vinda de um amigo, ```rem0obb```, foi implementarmos a biblioteca [LuaCpp](https://github.com/jordanvrtanoski/luacpp) para que pudéssemos utilizá-la como backend e oferecer automação completa da sessão de debug utilizando a linguagem Lua. Vale destacar que Lua é uma linguagem brasileira, o que a tornaria uma escolha perfeita e que se encaixaria muito bem neste projeto de debugger, também brasileiro.

###### Melhorar o Disassembler com o AsmJit

Planejávamos unificar o Disassembler Engine e o Assembler Engine em uma única biblioteca e ter um controle muito maior para que o usuário manipulasse o Disassembler gerado pelo Koi, a nível de baixa latência, permitindo inúmeras customizações. O plano era fazer isso integrando os backends que já utilizávamos, como o [Capstone Engine](https://www.capstone-engine.org/), o [Keystone Engine](https://www.keystone-engine.org/), e adicionar o [AsmJit Engine](https://asmjit.com/).

###### Utilizar a Microsoft Debug Engine para dar suporte a Kernel Mode

Por fim, a última funcionalidade que planejávamos para o futuro do Koi era o suporte a debug no kernel mode. Isso seria feito a partir da [Microsoft Debug Engine](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nn-dbgeng-idebugclient). Já havíamos feito um estudo completo sobre como essa funcionalidade funcionaria quando implementada, incluindo a criação da interface [COM](https://learn.microsoft.com/pt-br/windows/win32/learnwin32/what-is-a-com-interface-) e a implementação dos métodos básicos, inicialmente oferecendo suporte ao debugging via COM Port. No entanto, optamos por priorizar outras funcionalidades.

## Uma última mensagem

Desenvolver o KoiDbg foi, sem dúvida, um aprendizado e uma experiência que acredito que muitos deveriam vivenciar. Criar um debugger envolve e reforça muitos conceitos fundamentais de engenharia reversa, programação e Windows Internals — conhecimentos essenciais que todo pesquisador de segurança deveria dominar. Espero que, por meio deste artigo, tenha sido possível compartilhar um pouco dessa experiência e esclarecer diversas dúvidas sobre como o desenvolvimento de um debugger é feito. Criar o Koi certamente não foi uma tarefa fácil, exigiu muito tempo e esforço, mas a melhor parte foi, ao longo desse processo, encontrar diversas pessoas que apoiaram o projeto e até se tornaram parte dele, auxiliando em pesquisas, resolução de bugs e problemas. Agora, espero sinceramente que este artigo ajude muitas pessoas, seja para melhorar o Koi ou até para criar o seu próprio debugger, completamente do zero.

Keowu

![#116](/imgs/img116.gif)

## Referências

**"Um bom artigo não é feito sem referências; o conhecimento é construído pela comunidade. Ninguém constrói conhecimento sozinho."** Sendo assim, deixo minha gratidão à pesquisa de outras pessoas sensacionais que, assim como eu, compartilham o amor pela pesquisa e pela escrita (utilizando a norma ABNT para demonstrar o máximo de respeito a cada um de vocês, escritores).


- OGILVIE, Duncan. **TitanEngine.** [S. l.]. Disponível em: https://github.com/x64dbg/TitanEngine.
- OGILVIE, Duncan. **x64dbg.** [S. l.]. Disponível em: https://github.com/x64dbg/x64dbg.
- DONIEC, Aleksandra. **From a C Project Through Assembly to ShellCode Paper.** [S. l.]. Disponível em: https://vxug.fakedoma.in/papers/VXUG/Exclusive/FromaCprojectthroughassemblytoshellcodeHasherezade.pdf.
- MISIAK. Tim. **Writing a debugger from scratch.** [S. l.]. Disponível em: https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-1/.
REDP. **PsKernelRangeList on arm64 kernel** [S. l.]. Disponível em: https://redplait.blogspot.com/2020/04/pskernelrangelist-on-arm64-kernel.html.
- ARZILLI. Alessandro. **Notes on Hardware Breakpoints and Watchpoints** [S. l.]. Disponível em: https://aarzilli.github.io/debugger-bibliography/hwbreak.html.
- George. **async_wake-fun** [S. l.]. Disponível em: https://github.com/ninjaprawn/async_wake-fun/blob/6ffb822e153fd98fc6f9d09604317f316c3b0577/async_wake_ios/kdbg.c#L686.
- SIGUZA. **ARM64 - spsr_el1 Explanation.** [S. l.]. Disponível em: https://stackoverflow.com/a/69487245.
- ODZHAN. **Delegated NT DLL.** [S. l.]. Disponível em: https://modexp.wordpress.com/2024/02/13/delegated-nt-dll/.

- ODZHAN. **Windows Data Structures and Callbacks.** [S. l.]. Disponível em: https://modexp.wordpress.com/2020/08/06/windows-data-structures-and-callbacks-part-1/#ftl.

Caros referenciados, em alguns casos, apenas os nicknames estavam disponíveis nas suas respectivas publicações. Caso precisem de alguma alteração, entrem em contato comigo.