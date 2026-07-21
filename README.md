# FISIONEURO — Sistema de Gestão da Clínica Médica

Sistema local (Flask + SQLite) com login, cadastro de pacientes, médicos e agenda de consultas.

## Como iniciar

Dê **duplo clique em `iniciar.bat`** — ele já ativa o ambiente virtual e sobe o servidor.

Depois acesse no navegador: **http://localhost:3001**

Login inicial:
- Usuário: `admin`
- Senha: `admin123`

Troque a senha em "Alterar senha" no menu superior após o primeiro acesso.

## Iniciar manualmente (alternativa)

```
cd "C:\Users\HP\Desktop\clinica_medica"
.\venv\Scripts\python.exe app.py
```

## Estrutura

- `app.py` — rotas e lógica do sistema
- `db.py` / `schema.sql` — acesso e estrutura do banco SQLite
- `clinica.db` — arquivo do banco de dados (criado automaticamente, contém todos os dados)
- `templates/` — páginas HTML
- `static/css/style.css` — estilo visual
- `venv/` — ambiente virtual Python com o Flask instalado

## Histórico permanente

As **receitas** e os **acompanhamentos/evoluções** ficam **armazenados de forma permanente** no banco (`clinica.db`) e aparecem sempre no prontuário do paciente (Pacientes → Editar). As receitas **não podem ser excluídas** — fazem parte do histórico definitivo do paciente.

## Backup

- **Automático:** a cada primeiro acesso do dia, o sistema cria uma cópia do banco em `backups/clinica_AAAA-MM-DD.db`. Assim o histórico fica protegido mesmo em caso de problema.
- **Manual (recomendado periodicamente):** copie o arquivo `clinica.db`, a pasta `uploads/` (exames anexados) e a pasta `backups/` para um pendrive ou nuvem (Google Drive/OneDrive).

Para resetar tudo, apague `clinica.db` e o conteúdo de `uploads/`, depois rode `iniciar.bat` novamente (ele recria o banco com o usuário admin padrão).

## Atendimento: Totem, Balcão e Telão

O sistema tem um fluxo completo de recepção por senha:

- **Totem (entrada):** abra `http://localhost:3001/totem` no computador/tablet da entrada. O paciente digita o CPF (opcional) e retira a senha (normal ou prioritária). Se o CPF tiver agendamento no dia, a senha já vem vinculada ao médico. **Não exige login** — é a tela pública do totem.
- **Balcão (atendente):** menu **Balcão**. O atendente chama a próxima senha (aparece no telão), identifica paciente/médico/horário e escolhe **Particular** ou **Convênio**:
  - *Particular:* digita o valor, escolhe a forma de pagamento, salva e clica em **Emitir recibo** (PDF).
  - *Convênio:* informa convênio, carteirinha e o nº de autorização (obtido no portal do convênio), salva e clica em **Imprimir autorização** (PDF) para o paciente assinar.
  - Depois clica em **Encaminhar ao médico** e, quando a sala estiver livre, em **Chamar no telão**.
- **Telão (sala de espera):** abra `http://localhost:3001/telao` em tela cheia (tecla F11) na TV da recepção. Atualiza sozinho e mostra a senha chamada e para onde ir (balcão ou sala do médico). **Não exige login.**

Para a chamada mostrar a **sala do médico**, preencha o campo **Sala / consultório** no cadastro de cada médico. O tipo (particular/convênio) também pode ser definido já no agendamento (tela da Agenda).

### Atendimento do médico

Na lista **"Aguardando o médico"** do balcão, o botão **🩺 Atendimento médico** abre a tela do consultório, onde o médico:

- Vê o paciente, o médico e o **convênio** (nome, carteirinha e autorização, quando for convênio).
- Registra **observações do atendimento** (evolução), que ficam no prontuário do paciente.
- Emite **receita simples (1 via)**, **receita controlada (2 vias)** ou **solicitação de exames**, já prontas para impressão (botões de imprimir/PDF na tela do documento).

Todas as evoluções e receitas também aparecem no prontuário (Pacientes → Editar).

## Acesso do médico (cada médico só vê seus pacientes)

Cada médico só enxerga e atende **os pacientes vinculados a ele**, e **somente o médico** emite/imprime as receitas dos seus pacientes. Para configurar:

1. **Crie um login para cada médico:** menu **Usuários → Novo usuário**, perfil **Médico**, e selecione **qual médico** é aquele usuário.
2. **Vincule os pacientes ao médico (feito pelo administrador):** menu **Médicos → botão "Pacientes"** na linha do médico. Marque quais pacientes são atendidos por ele (há busca por nome/CPF e "marcar todos"). Um paciente pode ser vinculado a vários médicos, cada um pela sua tela.
3. Quando o **médico** faz login, ele vê apenas seus pacientes na lista, na agenda e no atendimento, e é o único que emite/imprime as receitas deles (receita normal em 1 via, controlada em 2 vias), na hora da consulta.

Observação: a recepção e o admin continuam vendo/cadastrando todos os pacientes e fazendo o balcão, mas **não emitem receitas** — isso é exclusivo do médico do paciente. O vínculo médico–paciente é cadastrado **apenas pelo administrador** (não aparece dentro da ficha de cada paciente).

## Receitas e solicitações de exames

Na tela de editar paciente há a seção **"Receitas e solicitações de exames"** com o botão **+ Nova receita / exame**. Preencha medicamentos e/ou exames, escolha o médico e gere o documento. Na tela do documento você tem:

- **🖨️ Imprimir** — abre o diálogo de impressão do Windows; basta escolher a impressora da rede.
- **⬇️ Baixar PDF** — gera um PDF profissional do documento (para arquivar ou anexar).
- **WhatsApp** — abre o WhatsApp já com a mensagem preenchida (usa o telefone do paciente, se cadastrado). Para enviar o documento em si, baixe o PDF e anexe na conversa.
- **E-mail** — abre seu programa de e-mail com o texto preenchido. Anexe o PDF baixado se quiser enviar o documento formatado.

Para personalizar o **nome e endereço da clínica** que aparecem no cabeçalho da receita, edite as linhas `CLINICA_NOME` e `CLINICA_INFO` no início do arquivo `app.py` (seção "Receitas").

## Anexos e observações do paciente

Na tela de editar paciente há um campo **Observações** e um campo para **anexar arquivos** (exames, laudos, PDFs, imagens, Word, Excel — até 20 MB cada). Os arquivos ficam salvos na pasta `uploads/` e podem ser baixados ou removidos pela própria tela do paciente. Para anexar arquivos a um paciente novo, salve-o primeiro; a tela então mostra a área de anexos.

## Perfis de usuário

- **admin**: acesso total, cadastra médicos e usuários
- **medico** / **recepcao**: acesso a pacientes e agenda

## Parar o servidor

Feche a janela do terminal aberta pelo `iniciar.bat`, ou pressione `Ctrl+C` nela.
