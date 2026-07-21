@echo off
REM Clique com o botao direito neste arquivo e escolha "Executar como administrador"
echo Liberando a porta 3001 no Firewall do Windows...
netsh advfirewall firewall add rule name="FISIONEURO Clinica 3001" dir=in action=allow protocol=TCP localport=3001
echo.
echo Pronto! Os outros aparelhos ja podem abrir o sistema pela rede.
pause
