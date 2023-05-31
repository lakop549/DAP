@echo off
 :: BatchGotAdmin
 :-------------------------------------
 REM  --> Check for permissions
 >nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
 if '%errorlevel%' NEQ '0' (
     echo ������ ������ ��û�ϴ� ���Դϴ�...
     goto UACPrompt
 ) else ( goto gotAdmin )

:UACPrompt
     echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
     echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
     exit /B

:gotAdmin
     if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
     pushd "%CD%"
     CD /D "%~dp0"
 :--------------------------------------

mkdir W1~82
mkdir W1~82\log
mkdir W1~82\good
mkdir W1~82\bad
mkdir W1~82\action
mkdir W1~82\Score

SET AccountScore=0
SET AccountScore3=0
SET AccountScore2=0
SET ServiceScore=0
SET ServiceScore1=0
SET ServiceScore2=0
SET ServiceScore3=0
SET PatchScore=0
SET PatchScore2=0
SET PatchScore3=0
SET LogScore=0
SET LogScore1=0
SET LogScore2=0
SET LogScore3=0
SET SecureScore=0
SET SecureScore2=0
SET SecureScore3=0

echo 			                        [W-01] ~ [W-82]������ �׸��� �����մϴ�. >>  W1~82\report.txt
echo. >>  W1~82\report.txt
echo Windows Server 2012 R2�� �������� ���۵� �ڵ��Դϴ�. >>  W1~82\report.txt
echo ���� ������ ���ؼ��� ������ �������� ���� ���� �� �ֽ��ϴ�. >>  W1~82\report.txt
echo bad�׸񿡼� ��ȣ �ڿ� S�� �ٴ� �׸��� ����ڿ� �����Ͽ� ���� �����ؾ��ϴ� �׸��Դϴ�. >>  W1~82\report.txt
echo bad�׸񿡼� ��ȣ �ڿ� SS�� ������ Windows Server 2012 ���� ���������� �ش��ϱ⿡  >>  W1~82\report.txt
echo ���� �����ؾ� �ϴ� �׸��Դϴ�. >>  W1~82\report.txt
echo ------------------------------------------------------------------------------- >>  W1~82\report.txt

echo. >>  W1~82\report.txt

echo. >>  W1~82\report.txt

echo [W-01]\t Administrator ���� �̸� ���� >> W1~82\report.txt
echo. >>  W1~82\report.txt

net user > account.txt
net user > W1~82\log\[W-01]log.txt
net user >> W1~82\report.txt
echo. >>  W1~82\report.txt

type account.txt | find /I "Administrator" > NUL
if %errorlevel% EQU 0 (
	echo [W-01]  Administrator ������ ������ - [���] > W1~82\bad\[W-01]bad.txt 
	echo [W-01] ����- ���α׷�- ������- ��������- ���� ���� ��å - ���� ��å - ���ȿɼ� >> W1~82\action\[W-01]action.txt
	echo [W-01] ����: Administrator ���� �̸� �ٲٱ⸦ �����ϱ� ����� ���� �̸����� ���� >> W1~82\action\[W-01]action.txt
	echo [W-01]  Administrator ������ ������ - [���] >> W1~82\report.txt
	echo ����- ���α׷�- ������- ��������- ���� ���� ��å - ���� ��å - ���ȿɼ� >> W1~82\report.txt
	echo ����: Administrator ���� �̸� �ٲٱ⸦ �����ϱ� ����� ���� �̸����� ���� >> W1~82\report.txt

) else (
	echo [W-01] Administrator ������ �������� ���� - [��ȣ] > W1~82\good\[W-01]good.txt
	echo [W-01] Administrator ������ �������� ���� - [��ȣ] >> W1~82\report.txt
	SET/a AccountScore = %AccountScore%+12
	SET/a AccountScore3 = %AccountScore3%+1
)
echo. >>  W1~82\report.txt

del account.txt


echo. >>  W1~82\report.txt

echo [W-02] Guest ���� ���� >>  W1~82\report.txt
echo. >>  W1~82\report.txt

net user guest > W1~82\log\[W-02]log.txt
net user guest | find "Ȱ�� ����" >>  W1~82\report.txt

echo. >>  W1~82\report.txt
net user guest | find "Ȱ�� ����" | find "�ƴϿ�" > NUL
if %errorlevel% EQU  0 (
	echo [W-02] Guest ������ ��Ȱ��ȭ�Ǿ� ���� - [��ȣ] >> W1~82\good\[W-02]good.txt 
	echo [W-02] Guest ������ ��Ȱ��ȭ�Ǿ� ���� - [��ȣ] >>  W1~82\report.txt 	
	SET/a AccountScore = %AccountScore%+12
	SET/a AccountScore3 = %AccountScore3%+1	
) else (
	echo [W-02] Guest ������ Ȱ��ȭ�Ǿ� ���� -  [���] >> W1~82\bad\[W-02]bad.txt
	echo ����- ����- LUSRMGR.MSC �����- GUEST- �Ӽ� ���� ��� ���Կ� üũ >> W1~82\action\[W-02]action.txt
	echo [W-02] Guest ������ Ȱ��ȭ�Ǿ� ���� -  [���] >>  W1~82\report.txt
	echo ����- ����- LUSRMGR.MSC �����- GUEST- �Ӽ� ���� ��� ���Կ� üũ >>  W1~82\report.txt
)
echo. >>  W1~82\report.txt


echo. >>  W1~82\report.txt

echo [W-03] ���ʿ��� ���� ���� >>  W1~82\report.txt
echo. >>  W1~82\report.txt

net user > W1~82\log\[W-03]log.txt
net user >>  W1~82\report.txt
echo. >>  W1~82\report.txt

echo [W-03] ���ʿ��� ������ �����ϴ� ��� - [���] > W1~82\bad\[W-03S]bad.txt
echo W1~82\log\[W-03]account.txt������ Ȯ���� "net user ������ /delete" �� �Է��Ͽ� > W1~82\action\[W-03]action.txt
echo ���ʿ��� ������ �����Ͻÿ� >> W1~82\action\[W-03]action.txt
echo ����, �� ���� �κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ� �����׸� �������� 3���� �ο��� �ֽʽÿ�. >> W1~82\action\[W-03]action.txt
echo [W-03] ���ʿ��� ������ �����ϴ� ��� - [���] >>  W1~82\report.txt
echo W1~82\log\[W-03]account.txt������ Ȯ���� "net user ������ /delete" �� �Է��Ͽ� >>  W1~82\report.txt
echo ���ʿ��� ������ �����Ͻÿ� >>  W1~82\report.txt
echo ����, �� ���� �κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ� �����׸� �������� 12���� �ο��� �ֽʽÿ�. >>  W1~82\report.txt

echo. >>  W1~82\report.txt


echo. >>  W1~82\report.txt

echo [W-04] ���� ��� �Ӱ谪 ����

net accounts | find "�Ӱ谪" > W1~82\log\[W-04]log.txt
net accounts | find "�Ӱ谪" > thres.txt
net accounts | find "�Ӱ谪" >>  W1~82\report.txt
echo. >>  W1~82\report.txt

for /f "tokens=3" %%a in (thres.txt) do set thres=%%a
if %thres% leq 5 (
	echo [W-04] �Ӱ谪�� 5 ���ϰ����� �����Ǿ� ���� - [��ȣ] >> W1~82\good\[W-04]good.txt 
	echo [W-04] �Ӱ谪�� 5 ���ϰ����� �����Ǿ� ���� - [��ȣ] >>  W1~82\report.txt 
	SET/a AccountScore = %AccountScore%+12
	SET/a AccountScore3 = %AccountScore3%+1
) else (
	echo [W-04] �Ӱ谪�� 6 �̻����� �����Ǿ� ���� - [���] > W1~82\bad\[W-04]bad.txt
	echo ���� - ���� - secpol.msc - ���� ��å - ���� ��� ��å >> W1~82\action\[W-04]action.txt
	echo ���� ��� �Ӱ谪�� 5���Ϸ� ����  >> W1~82\action\[W-04]action.txt
	echo [W-04] �Ӱ谪�� 6 �̻����� �����Ǿ� ���� - [���] >>  W1~82\report.txt
	echo ���� - ���� - secpol.msc - ���� ��å - ���� ��� ��å >>  W1~82\report.txt
	echo ���� ��� �Ӱ谪�� 5���Ϸ� ����  >>  W1~82\report.txt

)
echo. >>  W1~82\report.txt

del thres.txt


echo. >>  W1~82\report.txt

echo [W-05] �ص� ������ ��ȣȭ�� ����Ͽ� ��ȣ ���� ����

secedit /export /cfg secpol.txt   
echo f | Xcopy "secpol.txt" "W1~82\log\[W-05]log.txt"
type secpol.txt | find /I "ClearTextPassword" >>  W1~82\report.txt
echo. >>  W1~82\report.txt

type secpol.txt | find /I "ClearTextPassword" | find "0" > NUL
if %errorlevel% EQU 0 (
	echo [W-05] '��� �� ��'���� �����Ǿ� ���� - [��ȣ] > W1~82\good\[W-05]good.txt
	echo [W-05] '��� �� ��'���� �����Ǿ� ���� - [��ȣ] >>  W1~82\report.txt
	SET/a AccountScore = %AccountScore%+12
	SET/a AccountScore3 = %AccountScore3%+1
) else (
	echo [W-05] '���'���� �����Ǿ� ���� - [���] > W1~82\bad\[W-05]bad.txt
	echo ����-����-SECPOL.MSC-���� ��å-��ȣ ��å - �ص� ������ ��ȣȭ�� ����Ͽ� ��ȣ ���� ���� Ȯ�� �ص� ������ ��ȣȭ�� ����Ͽ� ��ȣ ������ ��� �� ������ ���� >> W1~82\action\[W-05]action.txt
	echo [W-05] '���'���� �����Ǿ� ���� - [���] >>  W1~82\report.txt
	echo ����-����-SECPOL.MSC-���� ��å-��ȣ ��å - �ص� ������ ��ȣȭ�� ����Ͽ� ��ȣ ���� ���� Ȯ�� �ص� ������ ��ȣȭ�� ����Ͽ� ��ȣ ������ ��� �� ������ ���� >>  W1~82\report.txt
)
echo. >>  W1~82\report.txt

del secpol.txt


echo. >>  W1~82\report.txt

echo [W-06] ������ �׷쿡 �ּ����� ����� ���� >>  W1~82\report.txt
echo. >>  W1~82\report.txt

net localgroup administrators | find /v "����� �� �����߽��ϴ�." > W1~82\log\[W-06]log.txt
net localgroup administrators | find /v "����� �� �����߽��ϴ�." >>  W1~82\report.txt
echo. >>  W1~82\report.txt

echo [W-06] Administrators �׷쿡 ���ʿ��� ������ ������ �����ϴ� ��� - [���] > W1~82\bad\[W-06S]bad.txt
echo W1~82\log\[W-06]log.txt ������ Ȯ���� ������ �׷쿡 ���Ե� ���ʿ��� ������ Ȯ��, ����ڿ� �����Ͽ� >> W1~82\action\[W-06]action.txt
echo ����-����-LUSRMGR.MSC-�׷�-Administrators-�Ӽ�-Administrators �׷쿡�� ���ʿ� ���� ���� �� �׷� ���� >> W1~82\action\[W-06]action.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, �����׸� �������� 12���� �ο��� �ֽʽÿ�. >> W1~82\action\[W-06]action.txt

echo [W-06] Administrators �׷쿡 ���ʿ��� ������ ������ �����ϴ� ��� - [���] >>  W1~82\report.txt
echo W1~82\log\[W-06]log.txt ������ Ȯ���� ������ �׷쿡 ���Ե� ���ʿ��� ������ Ȯ��, ����ڿ� �����Ͽ� >>  W1~82\report.txt
echo ����-����-LUSRMGR.MSC-�׷�-Administrators-�Ӽ�-Administrators �׷쿡�� ���ʿ� ���� ���� �� �׷� ���� >>  W1~82\report.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, �����׸� �������� ���� �ο��� �ֽʽÿ�. >>  W1~82\report.txt

echo. >>  W1~82\report.txt


echo. >>  W1~82\report.txt

echo [W-07] ���� ���� �� ����� �׷� ���� >>  W1~82\report.txt
echo. >>  W1~82\report.txt

net share > W1~82\log\[W-07]log.txt
net share >>  W1~82\report.txt
echo. >>  W1~82\report.txt

echo [W-07] �Ϲ� ���� ���丮�� ���� ���ѿ� Everyone ������ �ִ� ��� - [���] > W1~82\bad\[W-07S]bad.txt
echo W1~82\log\[W-07]log.txt ���Ͽ��� ������ ����ǰ� �ִ� ���� ����� Ȯ���� ��� ���ѿ��� Everyone���� �� ������ ���� >> W1~82\action\[W-07]action.txt
echo ����-����-FSMGMT.MSC-����-��� ���ѿ��� Everyone���� �� ������ �����ϰ� ������ �ʿ��� ������ ������ ���� �߰� >> W1~82\action\[W-07]action.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >> W1~82\action\[W-07]action.txt

echo [W-07] �Ϲ� ���� ���丮�� ���� ���ѿ� Everyone ������ �ִ� ��� - [���] >>  W1~82\report.txt
echo W1~82\log\[W-07]log.txt ���Ͽ��� ������ ����ǰ� �ִ� ���� ����� Ȯ���� ��� ���ѿ��� Everyone���� �� ������ ���� >>  W1~82\report.txt
echo ����-����-FSMGMT.MSC-����-��� ���ѿ��� Everyone���� �� ������ �����ϰ� ������ �ʿ��� ������ ������ ���� �߰� >>  W1~82\report.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >>  W1~82\report.txt

echo. >>  W1~82\report.txt


echo. >> W1~82\report.txt

echo [W-08] �ϵ��ũ �⺻ ���� ���� >> W1~82\report.txt
SET/a W8S=0

net share > log.txt
net share | find /v "����� �� �����߽��ϴ�." > W1~82\log\[W-08]log.txt

type log.txt | findstr /I "C$ D$ IPC$" > NUL
if %errorlevel% EQU 0 (
	echo [W-08] �ϵ��ũ �⺻ ���� ���ŵ� - [��ȣ] > W1~82\good\[W-08]good.txt
	echo [W-08] �ϵ��ũ �⺻ ���� ���ŵ� - [��ȣ] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+6
	SET/a W8S=1
) else (
	echo [W-08] �ϵ��ũ �⺻ ���� ���� �� �� - [���] > W1~82\bad\[W-08]bad.txt
	echo [W-08] �ϵ��ũ �⺻ ���� ���� �� �� - [���] >> W1~82\report.txt
	echo [W-08]log.txt ������ Ȯ���ϰ� �ϵ��ũ �⺻ ������ �����Ͻÿ� > W1~82\action\[W-08]action.txt
	echo ����-����-FSMGMT.MSC-����-�⺻��������-���콺 ��Ŭ��-���� ���� >>  W1~82\action\[W-08]action.txt
	echo [W-08]log.txt ������ Ȯ���ϰ� �ϵ��ũ �⺻ ������ �����Ͻÿ� >> W1~82\report.txt
	echo ����-����-FSMGMT.MSC-����-�⺻��������-���콺 ��Ŭ��-���� ���� >> W1~82\report.txt
)

del log.txt

reg query "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" | findstr /I "autoshare" >> W1~82\log\[W-08-2]log.txt
reg query "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" | findstr /I "autoshare" >> reg.txt

type reg.txt | find "0x0"
if %errorlevel% EQU 0 (
	echo [W-08] �ϵ��ũ �⺻ ���� ������Ʈ�� �� 0 - [��ȣ] > W1~82\good\[W-08]good.txt 
	echo [W-08] �ϵ��ũ �⺻ ���� ������Ʈ�� �� 0 - [��ȣ]  >> W1~82\report.txt 
	SET/a ServiceScore = %ServiceScore%+6
	SET/a W8S=1
) else (
	echo [W-08] �ϵ��ũ �⺻ ���� ������Ʈ�� �� 0 �ƴ� - [���] >> W1~82\bad\[W-08]bad.txt
	echo [W-08] �ϵ��ũ �⺻ ���� ������Ʈ�� �� 0 �ƴ� - [���] >> W1~82\report.txt
	echo [W-08] �ϵ��ũ �⺻ ���� ������Ʈ�� �� 0���� �����Ͻʽÿ� >>  W1~82\action\[W-08]action.txt
	echo [W-08] �ϵ��ũ �⺻ ���� ������Ʈ�� �� 0���� �����Ͻʽÿ� >> W1~82\report.txt
	echo ����-����-REGEDIT >>  W1~82\action\[W-08]action.txt
	echo ����-����-REGEDIT>> W1~82\report.txt
	echo �Ʒ� ������Ʈ�� ���� 0���� ���� (Ű���� ���� ��� ���� ����) >> W1~82\action\[W-08]action.txt
	echo �Ʒ� ������Ʈ�� ���� 0���� ���� (Ű���� ���� ��� ���� ����) >> W1~82\report.txt
	echo ��HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters\AutoShareServer�� >> W1~82\action\[W-08]action.txt
	echo ��HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters\AutoShareServer�� >> W1~82\report.txt
)
if %W8S% EQU 1 (
	SET/a ServiceScore3 = %ServiceScore3%+1
)

del reg.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-09] ���ʿ��� ���� ����  >> W1~82\report.txt
net start > W1~82\log\[W-09]log.txt

echo [W-09] �Ϲ������� ���ʿ��� ����(�Ʒ� ��� ����)�� ���� ���� ��� - [���] > W1~82\bad\[W-09S]bad.txt
echo W1~82\log\[W-09]log.txt ������ Ȯ���ϰ� ���ʿ��� ���� �����ϼ���(���̵� �� ǥ ����) >> W1~82\action\[W-09]action.txt
echo ����-����-SERVICES.MSC-���ش� ���񽺡�����-�Ӽ�, ���� ����-������, ���� ����-������������ ���ʿ��� ���� ���� >> W1~82\action\[W-09]action.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >> W1~82\action\[W-09]action.txt

echo [W-09] �Ϲ������� ���ʿ��� ����(�Ʒ� ��� ����)�� ���� ���� ��� - [���] >> W1~82\report.txt
echo W1~82\log\[W-09]log.txt ������ Ȯ���ϰ� ���ʿ��� ���� �����ϼ���(���̵� �� ǥ ����) >> W1~82\report.txt
echo ����-����-SERVICES.MSC-���ش� ���񽺡�����-�Ӽ�, ���� ����-������, ���� ����-������������ ���ʿ��� ���� ���� >> W1~82\report.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >>  W1~82\report.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-10] IIS���� ���� ���� >> W1~82\report.txt


net start > W1~82\log\[W-10]log.txt

type W1~82\log\[W-10]log.txt | find /i "IIS ADMIN Service" >nul 2>&1
if %errorlevel% EQU 0 (
  echo [W-10] IIS���񽺰� �ʿ����� ������ ����ϴ� ��� - [���] > W1~82\bad\[W-10]bad.txt
  echo ����ڿ� ���� �� IIS ���񽺰� ���ʿ��� �� >> W1~82\action\[W-10]action.txt
  echo ����-����-SERVICE.MSC-IISADMIN-�Ӽ�-���� ������ ��� ���� ���� �� ������ IIS ���� ���� >> W1~82\action\[W-10]action.txt

  echo [W-10] IIS���񽺰� �ʿ����� ������ ����ϴ� ��� - [���]  >> W1~82\report.txt
  echo ����ڿ� ���� �� IIS ���񽺰� ���ʿ��� ��  >> W1~82\report.txt
  echo ����-����-SERVICE.MSC-IISADMIN-�Ӽ�-���� ������ ��� ���� ���� �� ������ IIS ���� ����  >> W1~82\report.txt
) else (
  echo [W-10] IIS���񽺰� �ʿ����� �ʾ� �̿����� �ʴ� ��� - [��ȣ] > W1~82\good\[W-10]good.txt 
  echo [W-10] IIS���񽺰� �ʿ����� �ʾ� �̿����� �ʴ� ��� - [��ȣ]  >> W1~82\report.txt
  SET/a ServiceScore = %ServiceScore%+12
  SET/a ServiceScore3 = %ServiceScore3%+1
)

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-11] ���丮 ������ ���� >> W1~82\report.txt

type C:\inetpub\wwwroot\web.config | find /i "directoryBrowse" > W1~82\log\[W-11]log.txt
type C:\inetpub\wwwroot\web.config | find /i "directoryBrowse" > inform.txt

type inform.txt | find /i "false"
if %errorlevel% equ 0 (
	echo [W-11] ���丮 �˻��� ��� �� ������ �����Ǿ� ���� - [��ȣ] > W1~82\good\[W-11]good.txt
	echo [W-11] ���丮 �˻��� ��� �� ������ �����Ǿ� ���� - [��ȣ] >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
      SET/a ServiceScore3 = %ServiceScore3%+1
) else (
	echo [W-11] ���丮 �˻��� ������� �����Ǿ� ���� - [���] > W1~82\bad\[W-11]bad.txt
	echo [W-11] ������-��������-���ͳ��������� IIS����-�ش� �� ����Ʈ-IIS-���丮 �˻� ����-��� ���� ���� >> W1~82\action\[W-11]action.txt
	echo [W-11] ���丮 �˻��� ������� �����Ǿ� ���� - [���]  >> W1~82\report.txt
	echo [W-11] ������-��������-���ͳ��������� IIS����-�ش� �� ����Ʈ-IIS-���丮 �˻� ����-��� ���� ����  >> W1~82\report.txt
)

del  inform.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-12] IIS CGI ���� ����(scripts ���翩��) >> W1~82\report.txt
SET/a W12S=0

dir C:\inetpub /b > W1~82\log\[W-12]log.txt

type W1~82\log\[W-12]log.txt | find /I "scripts" > nul 
if %errorlevel% EQU 0 (
	echo [W-12] �ش� ���丮�� scripts ������ �����Ұ�� ������ - [���] > W1~82\bad\[W-12]bad.txt 
	echo [W-12] �ش� ���丮�� scripts ������ �����Ұ�� ������ - [���]  >> W1~82\report.txt 

) else (
	echo [W-12] scripts ������ �������� �ʴ� ��� - [��ȣ] >> W1~82\good\[W-12]good.txt
	echo [W-12] scripts ������ �������� �ʴ� ��� - [��ȣ] >> W1~82\report.txt 
      SET/a ServiceScore = %ServiceScore%+12
	SET/a W12S=1
	goto W12END
)

echo [W-12-1] IIS CGI ���� ���� >> W1~82\report.txt
 
icacls C:\inetpub\scripts | findstr /i "EVERYONE" > W1~82\log\[W-12]log.txt
type W1~82\log\[W-12]log.txt | findstr /i "W M F"
if %errorlevel% EQU 0 (
	echo [W-12] �ش� ���丮 Everyone�� ��� ����, ���� ����, ���� ������ �ο��Ǿ� �ִ� ��� - [���] >> W1~82\bad\[W-12]bad.txt 
	echo [W-12] Ž����-�ش� ���丮-�Ӽ�-����-Everyone�� ��� ����, ���� ����, ���� ���� ���� >> W1~82\action\[W-12]action.txt
	echo [W-12] �ش� ���丮 Everyone�� ��� ����, ���� ����, ���� ������ �ο��Ǿ� �ִ� ��� - [���]  >> W1~82\report.txt 
	echo [W-12] Ž����-�ش� ���丮-�Ӽ�-����-Everyone�� ��� ����, ���� ����, ���� ���� ����  >> W1~82\report.txt 

) else (
	echo [W-12-1] �ش� ���丮 Everyone�� ��� ����, ���� ����, ���� ������ �ο����� ���� ��� - [��ȣ] >> W1~82\good\[W-12]good.txt
	echo [W-12-1] �ش� ���丮 Everyone�� ��� ����, ���� ����, ���� ������ �ο����� ���� ��� - [��ȣ] >> W1~82\report.txt 
      SET/a ServiceScore = %ServiceScore%+6
	SET/a W12S=1

)
:W12END
if %W12S% EQU 1 (
	SET/a ServiceScore3 = %ServiceScore3%+1
)

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-13] IIS ���� ���丮 ���� ����

type C:\Windows\System32\inetsrv\config\applicationHost.config  > W1~82\log\[W-13]log.txt
type W1~82\log\[W-13]log.txt | find /I "enableParentPaths" | find /i "false" > log.txt
if errorlevel 0 goto W13B
if not errorlevel 0 goto W13G

:W13B
	echo [W-13] ���� ���丮 ���� ����� �������� ���� ��� - [���] > W1~82\bad\[W-13]bad.txt 
	echo [W-13] ������-��������-���ͳ� ��������(IIS) ������-�ش� ������Ʈ-IIS-ASP ����-�θ��� ��� �׸�-False ���� >> W1~82\action\[W-13]action.txt
	echo [W-13] ���� ���丮 ���� ����� �������� ���� ��� - [���] >> W1~82\report.txt 
	echo [W-13] ������-��������-���ͳ� ��������(IIS) ������-�ش� ������Ʈ-IIS-ASP ����-�θ��� ��� �׸�-False ���� >> W1~82\report.txt
	goto W13

:W13G
	echo [W-13] ���� ���丮 ���� ����� ������ ��� - [��ȣ] > W1~82\good\[W-13]good.txt
	echo [W-13] ���� ���丮 ���� ����� ������ ��� - [��ȣ]  >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
      SET/a ServiceScore3 = %ServiceScore3%+1
	goto W13

:W13
del log.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-14] IIS ���ʿ��� ���� ���� >> W1~82\report.txt

echo [W-14] �ش� �� ����Ʈ�� IIS Samples, IIS Help ������丮�� �����ϴ� ��� >> W1~82\bad\[W-14SS]bad.txt
echo [W-14] IIS 7.0(Windows 2008) �̻� ���� �ش���� ���� >> W1~82\action\[W-14SS]action.txt
echo [W-14] Windows 2000, 2003�� ��� Sample ���丮 Ȯ�� �� ���� >> W1~82\action\[W-14SS]action.txt
echo [W-14] ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >> W1~82\action\[W-14SS]action.txt

echo [W-14] �ش� �� ����Ʈ�� IIS Samples, IIS Help ������丮�� �����ϴ� ���  >> W1~82\report.txt
echo [W-14] IIS 7.0(Windows 2008) �̻� ���� �ش���� ���� >> W1~82\report.txt
echo [W-14] Windows 2000, 2003�� ��� Sample ���丮 Ȯ�� �� ����  >> W1~82\report.txt
echo [W-14] ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >>  W1~82\report.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-15] �� ���μ��� ���� ���� >> W1~82\report.txt

echo [W-15] �� ���μ����� ������ ������ �ο��� �������� �����ǰ� �ִ� ��� >> W1~82\bad\[W-15S]bad.txt
echo [W-15] ���� - ������ - �������� - ��ǻ�� ���� - ���� ����� �� �׷� - ����� ���� - nobody ���� �߰�  >> W1~82\action\[W-15S]action.txt
echo [W-15] ���� - ������ - �������� - ���� ���� ��å - ����� ���� �Ҵ� ����, " ���� �α׿�" �� "nobody" ���� �߰� >> W1~82\action\[W-15S]action.txt
echo [W-15] ���� - ���� - SERVICES.MSC - IIS Admin Service - �Ӽ� - [�α׿�] ���� ���� ������ nobody ���� �� �н����� �Է� >> W1~82\action\[W-15S]action.txt
echo [W-15] ���� - ���α׷� - ������ Ž���� - IIS�� ��ġ�� ���� �Ӽ� - [����] �ǿ��� nobody ������ �߰��ϰ� ��� ���� üũ >> W1~82\action\[W-15S]action.txt

echo. >> W1~82\action\[W-15S]action.txt
echo [W-15] "������Ʈ �������" - Ȩ ���丮 - �������α׷� ��ȣ(iis ���μ��� ���� ���� ) >> W1~82\action\[W-15S]action.txt
echo [W-15] ���� ,���� ,���� �� �������� �Ǿ��ִ� ��� >> W1~82\action\[W-15S]action.txt
echo [W-15] IIS ���μ����� �ý��� ������ ������ �ǹǷ� ��Ŀ�� IIS ���μ����� ������ ȹ���ϸ� �����ڿ� ���ϴ� ������ ���� �� �����Ƿ� ����  >> W1~82\action\[W-15S]action.txt
echo [W-15] ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >> W1~82\action\[W-15S]action.txt

echo [W-15] �� ���μ����� ������ ������ �ο��� �������� �����ǰ� �ִ� ��� >> W1~82\report.txt
echo [W-15] ���� - ������ - �������� - ��ǻ�� ���� - ���� ����� �� �׷� - ����� ���� - nobody ���� �߰�  >> W1~82\report.txt
echo [W-15] ���� - ������ - �������� - ���� ���� ��å - ����� ���� �Ҵ� ����, " ���� �α׿�" �� "nobody" ���� �߰� >> W1~82\report.txt
echo [W-15] ���� - ���� - SERVICES.MSC - IIS Admin Service - �Ӽ� - [�α׿�] ���� ���� ������ nobody ���� �� �н����� �Է� >> W1~82\report.txt
echo [W-15] ���� - ���α׷� - ������ Ž���� - IIS�� ��ġ�� ���� �Ӽ� - [����] �ǿ��� nobody ������ �߰��ϰ� ��� ���� üũ >> W1~82\report.txt

echo. >> W1~82\report.txt
echo [W-15] "������Ʈ �������" - Ȩ ���丮 - �������α׷� ��ȣ(iis ���μ��� ���� ���� ) >> W1~82\report.txt
echo [W-15] ���� ,���� ,���� �� �������� �Ǿ��ִ� ��� >> W1~82\report.txt
echo [W-15] IIS ���μ����� �ý��� ������ ������ �ǹǷ� ��Ŀ�� IIS ���μ����� ������ ȹ���ϸ� �����ڿ� ���ϴ� ������ ���� �� �����Ƿ� ���� >> W1~82\report.txt
echo [W-15] ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >>  W1~82\report.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-16] IIS ��ũ ������ >> W1~82\report.txt

set file=C:\inetpub\wwwroot

for /f "tokens=*" %%a in ('dir %file% /S /B') do echo %%a >> W1~82\log\[W-16]log.txt
WHERE /r C:\inetpub\wwwroot *.htm *.url *.html 
if %errorlevel% EQU 0 (
	echo [W-16] �ɺ��� ��ũ, aliases, �ٷΰ��� ���� ����� ����� - [���] >> W1~82\bad\[W-16]bad.txt
	echo [W-16] ��ϵ� �� ����Ʈ�� Ȩ ���丮�� �ִ� �ɺ��� ��ũ, aliases, �ٷΰ��� ������ �����Ͻʽÿ�. >> W1~82\action\[W-16]action.txt
	echo ������-�ý��� �� ����-��������-IIS������-�ش� ������Ʈ-�⺻ ����-"���� ���"���� Ȩ ���丮 ��ġ Ȯ�� >> W1~82\action\[W-16]action.txt
	echo ���� ��ο� �Էµ� Ȩ ���丮�� �̵��Ͽ� �ٷΰ��� ������ ���� >> W1~82\action\[W-16]action.txt

	echo [W-16] �ɺ��� ��ũ, aliases, �ٷΰ��� ���� ����� ����� - [���] >> W1~82\report.txt
	echo [W-16] ��ϵ� �� ����Ʈ�� Ȩ ���丮�� �ִ� �ɺ��� ��ũ, aliases, �ٷΰ��� ������ �����Ͻʽÿ�. >> W1~82\report.txt
	echo ������-�ý��� �� ����-��������-IIS������-�ش� ������Ʈ-�⺻ ����-"���� ���"���� Ȩ ���丮 ��ġ Ȯ�� >> W1~82\report.txt
	echo ���� ��ο� �Էµ� Ȩ ���丮�� �̵��Ͽ� �ٷΰ��� ������ ���� >> W1~82\report.txt

)	else (
	echo [W-16] �ɺ��� ��ũ, aliases, �ٷΰ��� ���� ����� ������� ���� - [��ȣ] >> W1~82\good\[W-16]good.txt
	echo [W-16] �ɺ��� ��ũ, aliases, �ٷΰ��� ���� ����� ������� ���� - [��ȣ] >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
      SET/a ServiceScore3 = %ServiceScore3%+1
)

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-17] IIS ���� ���ε� �� �ٿ�ε� ���� >> W1~82\report.txt 

type C:\inetpub\wwwroot\web.config | findstr /I "maxAllowedContentLength" >> W1~82\log\[W-17]log.txt
type C:\Windows\System32\inetsrv\config\applicationHost.config | findstr /I "bufferingLimit maxRequestEntityAllowed" >> W1~82\log\[W-17]log.txt
echo [W-17] �� ���μ����� ���� �ڿ��� �������� �ʴ� ��� (���ε� �� �ٿ�ε� �뷮 �� ����) - [���] >> W1~82\bad\[W-17S]bad.txt
echo [W-17] �� ���μ����� ���� �ڿ��� �������� �ʴ� ��� (���ε� �� �ٿ�ε� �뷮 �� ����) - [���] >> W1~82\report.txt

echo IIS 7���� �̻󿡼��� �⺻������ �������뷮 31457280byte(30MB), �ٿ�ε� 4194304byte(4MB), ���ε� 200000byte(0.2MB)�� �����ϰ� �ֽ��ϴ�. >> W1~82\action\[W-17]action.txt
echo ��ϵ� �� ����Ʈ�� ��Ʈ ���丮�� �ִ� web.config ���� �� security �Ʒ��� ���� �׸��� �߰��ϼ���. >> W1~82\action\[W-17]action.txt
echo ^<requestFiltering^> >> W1~82\action\[W-17]action.txt
echo     ^<requestLimits maxAllowedContentLength="�������뷮" /^> >> W1~82\action\[W-17]action.txt
echo ^<requestFiltering^> >>W1~82\action\[W-17]action.txt
echo - >> W1~82\action\[W-17]action.txt
echo %systemroot% \system32\inetsrv\config\applicationHost.config ���� �� ^<asp/^>�� ^<asp^>���̿� ���� �׸� �߰� >> W1~82\report.txt

echo ^<limits bufferingLimit="���ϴٿ�ε�뷮" maxRequestEntityAllowed="���Ͼ��ε�뷮" /^> >> W1~82\report.txt
echo IIS 7���� �̻󿡼��� �⺻������ �������뷮 31457280byte(30MB), �ٿ�ε� 4194304byte(4MB), ���ε� 200000byte(0.2MB)�� �����ϰ� �ֽ��ϴ�. >> W1~82\report.txt
echo ��ϵ� �� ����Ʈ�� ��Ʈ ���丮�� �ִ� web.config ���� �� security �Ʒ��� ���� �׸��� �߰��ϼ���. >> W1~82\report.txt
echo ^<requestFiltering^> >> W1~82\report.txt
echo     ^<requestLimits maxAllowedContentLength="�������뷮" /^> >> W1~82\report.txt
echo ^<requestFiltering^> >> W1~82\report.txt
echo - >> W1~82\report.txt
echo %systemroot% \system32\inetsrv\config\applicationHost.config ���� �� ^<asp/^>�� ^<asp^>���̿� ���� �׸� �߰� >> W1~82\report.txt
echo ^<limits bufferingLimit="���ϴٿ�ε�뷮" maxRequestEntityAllowed="���Ͼ��ε�뷮" /^> >> W1~82\report.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-18] IIS DB ���� ����� ���� >> W1~82\report.txt
SET/a W18S=0

type C:\inetpub\wwwroot\web.config | findstr /I "path="*."" >> pathSite.txt
type C:\inetpub\wwwroot\web.config | findstr /I "fileExtension" >> filterSite.txt
type C:\Windows\System32\inetsrv\config\applicationHost.config | findstr /I "path="*."" >> pathServer.txt
type C:\Windows\System32\inetsrv\config\applicationHost.config | findstr /I "fileExtension" >> filterServer.txt
type pathSite.txt | findstr /I "*.asa *.asax" >> W1~82\log\[W-18]Sitepathlog.txt
type filterSite.txt | findstr /I "asa asax" >> W1~82\log\[W-18]Sitefilterlog.txt
type pathServer.txt | findstr /I "*.asa *.asax" >> W1~82\log\[W-18]Serverpathlog.txt
type filterServer.txt | findstr /I "asa asax" >> W1~82\log\[W-18]Serverfilterlog.txt

type pathServer.txt | findstr /I "*.asa *.asax"
if not %errorlevel% EQU 0 (
	echo [W-18] ���� "ó�������"�� ��� �׸� asa, asax�� ��ϵǾ� ���� �ʽ��ϴ�. - [��ȣ] >> W1~82\good\[W-18]good.txt
	echo [W-18] ���� "ó�������"�� ��� �׸� asa, asax�� ��ϵǾ� ���� �ʽ��ϴ�. - [��ȣ] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+3
	SET/a W18S=1

)	else (
	echo [W-18] ���� "ó�������"�� ����׸� asa, asax�� ��ϵǾ� �ֽ��ϴ�. - [���] >> W1~82\bad\[W-18]bad.txt
	echo [W-18] IIS������-�ش缭��- IIS-"ó���� ����"����-��� �׸� *.asa �� *.asax�� �����ϼ���. >> W1~82\action\[W-18]action.txt
	echo [W-18] ���� "ó�������"�� ����׸� asa, asax�� ��ϵǾ� �ֽ��ϴ�. - [���] >> W1~82\report.txt
	echo [W-18] IIS������-�ش缭��- IIS-"ó���� ����"����-��� �׸� *.asa �� *.asax�� �����ϼ���. >> W1~82\report.txt
)

type filterServer.txt | find /I "true" | findstr /I "asa asax"
if not %errorlevel% EQU 0 (
	echo [W-18] ���� "��û ���͸�"�� asa, asax Ȯ���ڰ� false�� �����Ǿ� �ֽ��ϴ�. - [��ȣ] >> W1~82\good\[W-18]good.txt
	echo [W-18] ���� "��û ���͸�"�� asa, asax Ȯ���ڰ� false�� �����Ǿ� �ֽ��ϴ�. - [��ȣ] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+3
	SET/a W18S=1
)	else (
	echo [W-18] ���� "��û ���͸�"�� asa, asax Ȯ���ڰ� true�� �����Ǿ� �ֽ��ϴ�. - [���] >> W1~82\bad\[W-18]bad.txt
	echo [W-18] IIS������-�ش缭��-IIS-"��û ���͸�"����-asa �� asax Ȯ���ڸ� false�� �����ϼ���. >> W1~82\action\[W-18]action.txt
	echo [W-18] ���� "��û ���͸�"�� asa, asax Ȯ���ڰ� true�� �����Ǿ� �ֽ��ϴ�. - [���] >> W1~82\report.txt
	echo [W-18] IIS������-�ش缭��-IIS-"��û ���͸�"����-asa �� asax Ȯ���ڸ� false�� �����ϼ���. >> W1~82\report.txt

)

type pathSite.txt | findstr /I "*.asa *.asax"
if not %errorlevel% EQU 0 (
	echo [W-18] ����Ʈ "ó�������"�� ��� �׸� asa, asax�� ��ϵǾ� ���� �ʽ��ϴ�. - [��ȣ] >> W1~82\good\[W-18]good.txt
	echo [W-18] ����Ʈ "ó�������"�� ��� �׸� asa, asax�� ��ϵǾ� ���� �ʽ��ϴ�. - [��ȣ] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+3
	SET/a W18S=1
)	else (
	echo [W-18] ����Ʈ "ó�������"�� ����׸� asa, asax�� ��ϵǾ� �ֽ��ϴ�. - [���] >> W1~82\bad\[W-18]bad.txt
	echo [W-18] IIS������-�ش� �� ����Ʈ- IIS-"ó���� ����"����-��� �׸� *.asa �� *.asax�� �����ϼ���. >> W1~82\action\[W-18]action.txt
	echo [W-18] ����Ʈ "ó�������"�� ����׸� asa, asax�� ��ϵǾ� �ֽ��ϴ�. - [���] >> W1~82\report.txt
	echo [W-18] IIS������-�ش� �� ����Ʈ- IIS-"ó���� ����"����-��� �׸� *.asa �� *.asax�� �����ϼ���. >> W1~82\report.txt

)

type filterSite.txt | find /I "true" | findstr /I "asa asax"
if not %errorlevel% EQU 0 (
	echo [W-18] ����Ʈ "��û ���͸�"�� asa, asax Ȯ���ڰ� false�� �����Ǿ� �ֽ��ϴ�. - [��ȣ] >> W1~82\good\[W-18]good.txt
	echo [W-18] ����Ʈ "��û ���͸�"�� asa, asax Ȯ���ڰ� false�� �����Ǿ� �ֽ��ϴ�. - [��ȣ] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+3
	SET/a W18S=1
)	else (
	echo [W-18] ����Ʈ "��û ���͸�"�� asa, asax Ȯ���ڰ� true�� �����Ǿ� �ֽ��ϴ�. - [���] >> W1~82\bad\[W-18]bad.txt
	echo [W-18] IIS������-�ش� �� ����Ʈ-IIS-"��û ���͸�"����-asa �� asax Ȯ���ڸ� false�� �����ϼ���. >> W1~82\action\[W-18]action.txt
	echo [W-18] ����Ʈ "��û ���͸�"�� asa, asax Ȯ���ڰ� true�� �����Ǿ� �ֽ��ϴ�. - [���] >> W1~82\report.txt
	echo [W-18] IIS������-�ش� �� ����Ʈ-IIS-"��û ���͸�"����-asa �� asax Ȯ���ڸ� false�� �����ϼ���. >> W1~82\report.txt

)
if %W18S% EQU 1 (
	SET/a ServiceScore3 = %ServiceScore3%+1
)

del pathSite.txt
del filterSite.txt
del pathServer.txt
del filterServer.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-19] IIS ���� ���丮 ���� >> W1~82\report.txt

echo [W-19] �ش� �� ����Ʈ�� IIS Admin, IIS Adminpwd ���� ���丮�� �����ϴ� ��� - [���] > W1~82\bad\[W-19SS]bad.txt
echo [W-19] �ش� �� ����Ʈ�� IIS Admin, IIS Adminpwd ���� ���丮�� �����ϴ� ��� - [���] >> W1~82\report.txt

echo Windows 2003(6.0) �̻� ���� �ش� ���� ���� >> W1~82\action\[W-19]action.txt
echo Windows 2000(5.0) >> W1~82\action\[W-19]action.txt
echo ����-����-INETMGR �Է�-�� ����Ʈ- IISAdmin, IISAdminpwd ����-���� >> W1~82\action\[W-19]action.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >> W1~82\action\[W-19]action.txt


echo Windows 2003(6.0) �̻� ���� �ش� ���� ���� >> W1~82\report.txt
echo Windows 2000(5.0) >> W1~82\report.txt
echo ����-����-INETMGR �Է�-�� ����Ʈ- IISAdmin, IISAdminpwd ����-���� >> W1~82\report.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� �׸� �������� 3���� �ο��� �ֽʽÿ�. >>  W1~82\report.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-20] IIS ������ ���� ACL ���� >> W1~82\report.txt

icacls "C:\inetpub\wwwroot" >> W1~82\log\[W-20]log.txt

icacls "C:\inetpub\wwwroot" | findstr /I "Everyone" > NUL
if %errorlevel% EQU 0 (
  echo [W-20] Ȩ ���丮 ���� �ִ� ���� ���ϵ鿡 ���� Everyone ������ ���� - [���] > W1~82\bad\[W-20]bad.txt
  echo ����-����-INETMGR �Է�-����Ʈ Ŭ��-�ش� ������Ʈ-�⺻ ����- Ȩ ���丮 ���� ��� Ȯ�� >> W1~82\action\[W-20]action.txt
  echo Ž���⸦ �̿��Ͽ� Ȩ ���丮�� ��� ����-[����]�ǿ��� Everyone ���� Ȯ�� >> W1~82\action\[W-20]action.txt
  echo ���ʿ��� Everyone ������ �����Ͻʽÿ�. >> W1~82\action\[W-20]action.txt

  echo [W-20] Ȩ ���丮 ���� �ִ� ���� ���ϵ鿡 ���� Everyone ������ ���� - [���] >> W1~82\report.txt
  echo ����-����-INETMGR �Է�-����Ʈ Ŭ��-�ش� ������Ʈ-�⺻ ����- Ȩ ���丮 ���� ��� Ȯ�� >> W1~82\report.txt
  echo Ž���⸦ �̿��Ͽ� Ȩ ���丮�� ��� ����-[����]�ǿ��� Everyone ���� Ȯ�� >> W1~82\report.txt
  echo ���ʿ��� Everyone ������ �����Ͻʽÿ�. >> W1~82\report.txt
)	else (
	echo [W-20] Ȩ ���丮 ���� �ִ� ���� ���ϵ鿡 ���� Everyone ������ �������� ���� - [��ȣ] > W1~82\good\[W-20]good.txt
	echo [W-20] Ȩ ���丮 ���� �ִ� ���� ���ϵ鿡 ���� Everyone ������ �������� ���� - [��ȣ] >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
      SET/a ServiceScore3 = %ServiceScore3%+1
)

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-21] IIS Exec ��ɾ� �� ȣ�� ���� >> W1~82\report.txt

dir C:\Windows\System32\inetsrv /b > W1~82\log\[W-21]log.txt
dir C:\Windows\System32\inetsrv /b > list.txt

type list.txt | findstr /i /l ".htr .IDC .stm .shtm .shtml .printer .htw .ida .idq htr.dll idc.dll stm.dll shtm.dll shtml.dll printer.dll htw.dll ida.dll idq.dll" > W1~82\log\[W-21]detectlog.txt
type list.txt | findstr /i /l ".htr .IDC .stm .shtm .shtml .printer .htw .ida .idq htr.dll idc.dll stm.dll shtm.dll shtml.dll printer.dll htw.dll ida.dll idq.dll" > list2.txt
if errorlevel 1 goto W21G
if not errorlevel 1 goto W21B


:W21B
	echo [W-21] htr IDC stm shtm shtml printer htw ida idq�� ������ log���� Ȯ�� - [���] >> W1~82\bad\[W-21]bad.txt 
	echo [W-21] ���� - ���� - INETMGR - ������Ʈ - �ش� ������Ʈ - ó���� ���� ���� >> W1~82\action\[W-21]action.txt
	echo [W-21] ����� ���� ���� (htr idc stm shtm shtml printer htw ida idq) >> W1~82\action\[W-21]action.txt
	echo [W-21] htr IDC stm shtm shtml printer htw ida idq�� ������ log���� Ȯ�� - [���] >> W1~82\report.txt 
	echo [W-21] ���� - ���� - INETMGR - ������Ʈ - �ش� ������Ʈ - ó���� ���� ���� >> W1~82\report.txt
	echo [W-21] ����� ���� ���� (htr idc stm shtm shtml printer htw ida idq) >> W1~82\report.txt
	goto W21

:W21G
	echo [W-21] htr IDC stm shtm shtml printer htw ida idq�� ������������  - [��ȣ] >> W1~82\good\[W-21]good.txt
	echo [W-21] htr IDC stm shtm shtml printer htw ida idq�� ������������  - [��ȣ] >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
      SET/a ServiceScore3 = %ServiceScore3%+1
	goto W21

:W21
del list.txt
del list2.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-22] IIS Exec ��ɾ� �� ȣ�� ����(������Ʈ���� ���� ����) >> W1~82\report.txt
SET/a W22S=0

reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters /s | find /v "����" > W1~82\log\[W-22]log.txt
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters /s | find /v "����" > reg.txt
type reg.txt | find /I "SSIEnableCmdDirective" > NUL

if %errorlevel% EQU 1 (
	echo [W-22] ������Ʈ������ �������� �ʰų� IIS 6.0������ ��� - [��ȣ] >> W1~82\good\[W-22]good.txt
	echo [W-22] ������Ʈ������ �������� �ʰų� IIS 6.0������ ��� - [��ȣ] >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
	SET/a W22S=1
	goto W22
) else (
	echo [W-22] �ش� ������Ʈ������ ������ - [���] >> W1~82\bad\[W-22]bad.txt
	echo [W-22] �ش� ������Ʈ������ ������ - [���] >> W1~82\report.txt
	goto W22-1
)

:W22-1
echo [W-22] IIS Exec ��ɾ� �� ȣ�� ���� >> W1~82\report.txt

type reg.txt | find /I "SSIEnableCmdDirective" > ssl.txt

type ssl.txt | find "0x1"
if %errorlevel% EQU 1 (
	echo [W-22-1] ������Ʈ������ 0��  - [��ȣ] > W1~82\good\[W-22]good.txt
	echo [W-22-1] ������Ʈ������ 0��  - [��ȣ] >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
	SET/a W22S=1
	del  W1~82\bad\[W-22]bad.txt
) else (
	echo [W-22-1] �ش� ������Ʈ������ 1�� [���] >> W1~82\bad\[W-22]bad.txt
	echo ���� - ���� - REGEDIT - HKLM\SYSTEM\CurrentControlSet\Services\W32VC\Parameters �˻� > W1~82\action\[W-22]action.txt
	echo DWORD - SSIEnableCmdDirective ���� ã�� ���� 0���� �Է� >> W1~82\action\[W-22]action.txt

	echo [W-22-1] �ش� ������Ʈ������ 1�� [���] >> W1~82\report.txt
	echo ���� - ���� - REGEDIT - HKLM\SYSTEM\CurrentControlSet\Services\W32VC\Parameters �˻� >> W1~82\report.txt
	echo DWORD - SSIEnableCmdDirective ���� ã�� ���� 0���� �Է� >> W1~82\report.txt

)

:W22
if %W22S% EQU 1 (
	SET/a ServiceScore3 = %ServiceScore3%+1
)

del reg.txt
del ssl.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-23] IIS WebDAV ��Ȱ��ȭ >> W1~82\report.txt

type C:\Windows\System32\inetsrv\config\applicationHost.config > log.txt
type C:\Windows\System32\inetsrv\config\applicationHost.config > W1~82\log\[W-23]log.txt

type log.txt | findstr /I "webdav.dll" | find "true"
if errorlevel 1 goto W23G
if not errorlevel 1 goto W23B

:W23B
echo [W-23] WebDav�� ������ - [���] >> W1~82\bad\[W-23]bad.txt  
echo ���ͳ� ���� ����(IIS) ������ - ���� ���� - IIS - ISAPI �� CGI ���� ����, WebDAV ��뿩�� Ȯ�� (������ ��� ���) >> W1~82\action\[W-23]action.txt
echo ���ͳ� ���� ����(IIS) ������ - ���� ���� > IIS - "ISAPI �� CGI ����" ���� WebDAV �׸� ���� - �۾����� �����ϰų�, ���� - "Ȯ�� ��� ���� ���" üũ ����  >> W1~82\action\[W-23]action.txt
echo [W-23] WebDav�� ������ - [���] >> W1~82\report.txt  
echo ���ͳ� ���� ����(IIS) ������ - ���� ���� - IIS - ISAPI �� CGI ���� ����, WebDAV ��뿩�� Ȯ�� (������ ��� ���) >> W1~82\report.txt
echo ���ͳ� ���� ����(IIS) ������ - ���� ���� > IIS - "ISAPI �� CGI ����" ���� WebDAV �׸� ���� - �۾����� �����ϰų�, ���� - "Ȯ�� ��� ���� ���" üũ ����  >> W1~82\report.txt

goto W23

:W23G
echo [W-23] WebDav�� ������������  - [��ȣ] >> W1~82\good\[W-23]good.txt
echo [W-23] WebDav�� ������������  - [��ȣ] >> W1~82\report.txt
SET/a ServiceScore = %ServiceScore%+12
SET/a ServiceScore3 = %ServiceScore3%+1

goto W23


:W23
del log.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-24] NetBIOS ���ε� ���� ���� ���� >> W1~82\report.txt

wmic nicconfig where "TcpipNetbiosOptions<>null and ServiceName<>'VMnetAdapter'" get Description, TcpipNetbiosOptions > W1~82\log\[W-24]log.txt
wmic nicconfig where "TcpipNetbiosOptions<>null and ServiceName<>'VMnetAdapter'" get Description, TcpipNetbiosOptions > netb.txt

type netb.txt | findstr /I "0" > NUL
if %errorlevel% EQU 0 (
	 echo [w-24]  TCP/IP�� NetBIOS ���� ���ε��� ���� �Ǿ� ���� [��ȣ] > W1~82\good\[W-24]good.txt
	 echo [w-24]  TCP/IP�� NetBIOS ���� ���ε��� ���� �Ǿ� ���� [��ȣ] >> W1~82\report.txt
	 SET/a ServiceScore = %ServiceScore%+12
	 SET/a ServiceScore3 = %ServiceScore3%+1
) else (
	echo [W-24] TCP/IP�� NetBIOS ���� ���ε��� ���� �Ǿ����� ���� [���] > W1~82\bad\[W-24]bad.txt 
	echo [W-24] ���� - ���� - ncpa.cpl - ���� ���� ���� - �Ӽ� - TCP/IP - [�Ϲ�] �ǿ��� [���] Ŭ�� - [WINS] �ǿ��� TCP/IP���� "NetBIOS ��� �� ��" �Ǵ�, "NetBIOS over TCP/IP ��� �� ��" ���� >> W1~82\action\[W-24]action.txt

	echo [W-24] TCP/IP�� NetBIOS ���� ���ε��� ���� �Ǿ����� ���� [���] >> W1~82\report.txt 
	echo [W-24] ���� - ���� - ncpa.cpl - ���� ���� ���� - �Ӽ� - TCP/IP - [�Ϲ�] �ǿ��� [���] Ŭ�� - [WINS] �ǿ��� TCP/IP���� "NetBIOS ��� �� ��" �Ǵ�, "NetBIOS over TCP/IP ��� �� ��" ���� >> W1~82\report.txt

)

del netb.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-25] FTP ���� ���� ���� >> W1~82\report.txt

net start | find "Microsoft FTP Service" >  W1~82\log\[W-25]log.txt

net start | find "Microsoft FTP Service"
if %errorlevel% EQU 0 (
	echo [W-25] FTP ���񽺸� ����ϴ� ��� - [���] > W1~82\bad\[W-25]bad.txt
  echo FTP ���񽺰� ���ʿ��� ��� FTP���� ��� ���� >> W1~82\action\[W-25]action.txt
	echo ���� - ���� - SERVICES.MSC - FTP Publishing Service - �Ӽ� - [�Ϲ�] �ǿ��� "���� ����" ��� �� �� ���� ������ ��, FTP ���� ���� >> W1~82\action\[W-25]action.txt

	echo [W-25] FTP ���񽺸� ����ϴ� ��� - [���] >> W1~82\report.txt
  echo FTP ���񽺰� ���ʿ��� ��� FTP���� ��� ���� >> W1~82\report.txt
	echo ���� - ���� - SERVICES.MSC - FTP Publishing Service - �Ӽ� - [�Ϲ�] �ǿ��� "���� ����" ��� �� �� ���� ������ ��, FTP ���� ���� >> W1~82\report.txt

) else (
	echo [W-25] FTP ���񽺸� ������� �ʴ� ��� - [��ȣ] > W1~82\good\[W-25]good.txt
	echo [W-25] FTP ���񽺸� ������� �ʴ� ��� - [��ȣ] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+12
	SET/a ServiceScore3 = %ServiceScore3%+1
)

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-26] FTP ���丮 ���ٱ��� ���� >> W1~82\report.txt
 
icacls C:\inetpub\ftproot > W1~82\log\[W-26]log.txt

icacls C:\inetpub\ftproot | findstr /i "EVERYONE"
if %errorlevel% EQU 0 (
	echo [W-26] FTP Ȩ ���丮�� Everyone ������ �ִ� ��� - [���] >> W1~82\bad\[W-26]bad.txt
	echo [W-26] ���ͳ� ���� ���� IIS ���� - FTP ����Ʈ - �ش� FTP ����Ʈ - �Ӽ� - [Ȩ ���丮] �ǿ��� FTP Ȩ ���丮 Ȯ�� >> W1~82\action\[W-26]action.txt 
	echo [W-26] Ž���� - Ȩ ���丮 - �Ӽ� - [����] �ǿ��� Everyone ���� ���� >> W1~82\action\[W-26]action.txt

	echo [W-26] FTP Ȩ ���丮�� Everyone ������ �ִ� ��� - [���] >> W1~82\report.txt
	echo [W-26] ���ͳ� ���� ���� IIS ���� - FTP ����Ʈ - �ش� FTP ����Ʈ - �Ӽ� - [Ȩ ���丮] �ǿ��� FTP Ȩ ���丮 Ȯ�� >> W1~82\report.txt 
	echo [W-26] Ž���� - Ȩ ���丮 - �Ӽ� - [����] �ǿ��� Everyone ���� ���� >> W1~82\report.txt

) else (
	echo [W-26] ��ȣ FTP Ȩ ���丮�� Everyone ������ ���� ��� - [��ȣ] >> W1~82\good\[W-26]good.txt
	echo [W-26] ��ȣ FTP Ȩ ���丮�� Everyone ������ ���� ��� - [��ȣ] >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
      SET/a ServiceScore3 = %ServiceScore3%+1
)

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-27] Anonymous FTP ���� >> W1~82\report.txt

type C:\Windows\System32\inetsrv\config\applicationHost.config | find "anonymousAuthentication enabled" > W1~82\log\[W-27]log.txt
type C:\Windows\System32\inetsrv\config\applicationHost.config | find "anonymousAuthentication enabled" > log.txt

type log.txt | find "true" 
if %errorlevel% EQU 0 (
	echo [W-27] FTP �͸� ��� ���� - [���] > W1~82\bad\[W-27]bad.txt
	echo ������-��������-���ͳ� ���� ���� IIS ����-�ش� ������Ʈ-���콺 ��Ŭ��-FTP �Խ� �߰� > W1~82\action\[W-27]action.txt
	echo ���� ���� �������� ���� ȭ���� �͸� üũ �ڽ� ���� >> W1~82\action\[W-27]action.txt

	echo [W-27] FTP �͸� ��� ���� - [���] >> W1~82\report.txt
	echo ������-��������-���ͳ� ���� ���� IIS ����-�ش� ������Ʈ-���콺 ��Ŭ��-FTP �Խ� �߰� >> W1~82\report.txt
	echo ���� ���� �������� ���� ȭ���� �͸� üũ �ڽ� ���� >> W1~82\report.txt

) else (
	echo [W-27] FTP �͸� ����� ��� ���� - [��ȣ] > W1~82\good\[W-27]good.txt
	echo [W-27] FTP �͸� ����� ��� ���� - [��ȣ] >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
      SET/a ServiceScore3 = %ServiceScore3%+1
)

del log.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-28] FTP ���� ���� ���� >> W1~82\report.txt

type C:\Windows\System32\inetsrv\config\applicationHost.config | find /I "add ipAddress" > W1~82\log\[W-28]log.txt

echo [W-28] FTP ���� ���� ���� Ȯ�� - [���] > W1~82\bad\[W-28S]bad.txt
echo W1~82\log\[W-28]log.txt ������ Ȯ���ϰ� ����ڿ� �����Ͽ� ���ʿ��� �ּ��� ������ ���� �Ͻʽÿ�. >> W1~82\action\[W-28]action.txt
echo ��ġ ��� : ������-��������-���ͳ� ���� ����(IIS)����-�ش� ������Ʈ-FTP IPv4�ּ� �� ������ ���� >> W1~82\action\[W-28]action.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� �׸� �������� 3���� �ο��� �ֽʽÿ�. >> W1~82\action\[W-28]action.txt

echo [W-28] FTP ���� ���� ���� Ȯ�� - [���] >> W1~82\report.txt
echo W1~82\log\[W-28]log.txt ������ Ȯ���ϰ� ����ڿ� �����Ͽ� ���ʿ��� �ּ��� ������ ���� �Ͻʽÿ�. >> W1~82\report.txt
echo ��ġ ��� : ������-��������-���ͳ� ���� ����(IIS)����-�ش� ������Ʈ-FTP IPv4�ּ� �� ������ ���� >> W1~82\report.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� �׸� �������� 3���� �ο��� �ֽʽÿ�. >>  W1~82\report.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-29] DNS Zone Transfer ���� >> W1~82\report.txt
SET/a W29S=0

net start > W1~82\log\[W-29]log.txt
net start > log.txt

type log.txt | find "DNS Server"
if %errorlevel% EQU 1 (
	echo [W-29] DNS���񽺸� ������� �ʴ� ��� - [��ȣ] >> W1~82\good\[W-29]good.txt
	echo [W-29] DNS���񽺸� ������� �ʴ� ��� - [��ȣ] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+6
	SET/a W29S=1
) else (
	echo [W-29] DNS���񽺸� ����ϴ� ��� - [���] >> W1~82\bad\[W-29]bad.txt
	echo [W-29] DNS���񽺸� �ߴ��ϼ���. >> W1~82\action\[W-29]action.txt

	echo [W-29] DNS���񽺸� ����ϴ� ��� - [���] >> W1~82\report.txt
	echo [W-29] DNS���񽺸� �ߴ��ϼ���. >> W1~82\report.txt

)

reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s >> W1~82\log\[W-29]log.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | find /I "SecureSecondaries" >> reg.txt

type reg.txt | findstr /I "0x1 0x2"
if %errorlevel% EQU 1 (
	echo [W-29] ���� ���� ����� ���� �ʴ� ��� - [��ȣ] >> W1~82\good\[W-29]good.txt 
	echo [W-29] ���� ���� ����� ���� �ʴ� ��� - [��ȣ] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+6
	SET/a W29S=1
) else (
	echo [W-29] ���� ���� ����� �ϴ� ��� - [���] >> W1~82\bad\[W-29]bad.txt
	echo [W-29] W1~82\log\[W-29]log.txt ������ Ȯ���Ͽ� 'SecureSecondaries' ������Ʈ������ 0x0�̰ų� 0x3�� �ƴ� �׸��� ���� ���� ���� ���� >> W1~82\action\[W-29]action.txt
	echo [W-29] ����-����-DNSMGMT.MSC-�� ��ȸ ����-�ش� ����-�Ӽ�-���� ���� >> W1~82\action\[W-29]action.txt
	echo [W-29] ������ �����θ��� ������ ������ ���� IP �߰� >> W1~82\action\[W-29]action.txt

	echo [W-29] ���� ���� ����� �ϴ� ��� - [���] >> W1~82\report.txt
	echo [W-29] W1~82\log\[W-29]log.txt ������ Ȯ���Ͽ� 'SecureSecondaries' ������Ʈ������ 0x0�̰ų� 0x3�� �ƴ� �׸��� ���� ���� ���� ���� >> W1~82\report.txt
	echo [W-29] ����-����-DNSMGMT.MSC-�� ��ȸ ����-�ش� ����-�Ӽ�-���� ���� >> W1~82\report.txt
	echo [W-29] ������ �����θ��� ������ ������ ���� IP �߰� >> W1~82\report.txt
)
if %W29S% EQU 1 (
	SET/a ServiceScore3 = %ServiceScore3%+1
)


del log.txt
del reg.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-30] RDS (Remote Data Services)���� >> W1~82\report.txt

reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters" /s >> W1~82\log\[W-30]log.txt
reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters" /s >> log.txt

type log.txt | findstr "ADCLaunch" 
if errorlevel EQU 0 (
	echo [W-30] RDS(Remote Data Services) ���ŵ� (2008 �̻� ��ȣ) >> W1~82\good\[W-30SS]good.txt
	echo [W-30] RDS(Remote Data Services) ���ŵ� (2008 �̻� ��ȣ) >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
      SET/a ServiceScore3 = %ServiceScore3%+1
	goto W30
) else (
	echo [W-30] RDS(Remote Data Services) ���ŵ� (2008 �̸� ���) >> W1~82\bad\[W-30SS]bad.txt
	echo ����-����-inetmgr-������Ʈ ���� �� ������ ���丮���� msadc���� >> W1~82\action\[W-30SS]action.txt
	echo ������ ������Ʈ�� Ű/���丮 ����>> W1~82\action\[W-30SS]action.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\RDSServer.DataFactory >> W1~82\action\[W-30SS]action.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\AdvancedDataFactory >> W1~82\action\[W-30SS]action.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\VbBusObj.VbBusObjCls >> W1~82\action\[W-30SS]action.txt

	echo [W-30] RDS(Remote Data Services) ���ŵ� (2008 �̸� ���) >> W1~82\report.txt
	echo ����-����-inetmgr-������Ʈ ���� �� ������ ���丮���� msadc���� >> W1~82\report.txt
	echo ������ ������Ʈ�� Ű/���丮 ���� >> W1~82\report.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\RDSServer.DataFactory >> W1~82\report.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\AdvancedDataFactory >> W1~82\report.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\VbBusObj.VbBusObjCls >> W1~82\report.txt

	goto W30
)

:W30
del log.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-31] �ֽ� ������ ���� >> W1~82\report.txt

echo [W-31] �ֽ� �������� ��ġ���� �ʰų�, ���� ���� �� ����� �������� ���� ��� - [���] > W1~82\bad\[W-31S]bad.txt
echo [W-31] �ֽ� �������� ��ġ���� �ʰų�, ���� ���� �� ����� �������� ���� ��� - [���] >> W1~82\report.txt

echo ����-����-Winver�Է� >> W1~82\action\[W-31]action.txt
echo ������ ���� Ȯ�� �� �ֽ� ������ �ƴ� ��� "https://support.microsoft.com/ko-kr/lifecycle/search"���� �ֽ� ������ �ٿ�ε� �� ��ġ �Ǵ� �ڵ�������Ʈ�� Ȱ�����ּ���. >> W1~82\action\[W-31]action.txt
echo �����ͳ� ���� Windows�� ������� �̿��Ͽ� �����ϱ� ������ ������ ��ġ�ÿ��� ��Ʈ��ũ�� �и��� ���¿��� ��ġ �� ���� �����մϴ�.�� >> W1~82\action\[W-31]action.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >> W1~82\action\[W-31]action.txt


echo ����-����-Winver�Է� >> W1~82\report.txt
echo ������ ���� Ȯ�� �� �ֽ� ������ �ƴ� ��� "https://support.microsoft.com/ko-kr/lifecycle/search"���� �ֽ� ������ �ٿ�ε� �� ��ġ �Ǵ� �ڵ�������Ʈ�� Ȱ�����ּ���. >> W1~82\report.txt
echo �����ͳ� ���� Windows�� ������� �̿��Ͽ� �����ϱ� ������ ������ ��ġ�ÿ��� ��Ʈ��ũ�� �и��� ���¿��� ��ġ �� ���� �����մϴ�.�� >> W1~82\report.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >> W1~82\report.txt


echo.>> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-32] �ֽ� HOT FIX ���� >> W1~82\report.txt

echo [W-32] �ֽ� HotFix�� �ִ��� �ֱ������� ����� ������ ���ų�, �ֽ� HotFix�� �ݿ����� ���� ���, ���� PMS(Patch Management System) Agent�� ��ġ�Ǿ� ���� �ʰų�, ��ġ�Ǿ� ������ �ڵ���ġ������ ������� ���� ��� - [���] >> W1~82\bad\[W-32S]bad.txt
echo [W-32] �ֽ� HotFix�� �ִ��� �ֱ������� ����� ������ ���ų�, �ֽ� HotFix�� �ݿ����� ���� ���, ���� PMS(Patch Management System) Agent�� ��ġ�Ǿ� ���� �ʰų�, ��ġ�Ǿ� ������ �ڵ���ġ������ ������� ���� ��� - [���] >> W1~82\report.txt


echo ���� HOT FIX ���� ��� >> W1~82\action\[W-32]action.txt
echo "https://technet.microsoft.com/ko-kr/security/"���� ��ġ ����Ʈ�� ��ȸ�Ͽ�, ������ �ʿ��� ��ġ�� �����Ͽ� �������� ��ġ >> W1~82\action\[W-32]action.txt
echo. >> W1~82\action\[W-32]action.txt
echo �ڵ� HOT FIX ���� >> W1~82\action\[W-32]action.txt
echo Windows �ڵ� ������Ʈ ����� �̿��� ��ġ >> W1~82\action\[W-32]action.txt
echo ������-windows update >> W1~82\action\[W-32]action.txt
echo. >> W1~82\action\[W-32]action.txt
echo PMS��ġ >> W1~82\action\[W-32]action.txt
echo Agent�� ��ġ�Ͽ� �ڵ����� ������Ʈ �ǵ��� ������ >> W1~82\action\[W-32]action.txt
echo �� ������ġ �� Hot Fix ��� ���� �� �ý��� ������� �䱸�ϴ� ��찡 ��κ��̹Ƿ� �����ڴ� ���񽺿� ������ ���� �ð��뿡 ������ ��. >> W1~82\action\[W-32]action.txt
echo �� �Ϻ� Hot Fix�� ����ǰ��ִ� OS ���α׷��̳� ���߿� Application ���α׷��� ������ �� �� �����Ƿ� ��ġ ���� �� Application ���α׷��� �����ϰ�, �ʿ��ϴٸ� OS ���� �Ǵ� Application �����Ͼ�� Ȯ�� �۾��� ��ģ �� ��ġ�� ������ ��. >> W1~82\action\[W-32]action.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ��ġ ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >> W1~82\action\[W-32]action.txt

echo ���� HOT FIX ���� ��� >> W1~82\report.txt
echo "https://technet.microsoft.com/ko-kr/security/"���� ��ġ ����Ʈ�� ��ȸ�Ͽ�, ������ �ʿ��� ��ġ�� �����Ͽ� �������� ��ġ >> W1~82\report.txt
echo. >> W1~82\report.txt
echo �ڵ� HOT FIX ���� >> W1~82\report.txt
echo Windows �ڵ� ������Ʈ ����� �̿��� ��ġ >> W1~82\report.txt
echo ������-windows update >> W1~82\report.txt
echo. >> W1~82\report.txt
echo PMS��ġ >> W1~82\report.txt
echo Agent�� ��ġ�Ͽ� �ڵ����� ������Ʈ �ǵ��� ������ >> W1~82\report.txt
echo �� ������ġ �� Hot Fix ��� ���� �� �ý��� ������� �䱸�ϴ� ��찡 ��κ��̹Ƿ� �����ڴ� ���񽺿� ������ ���� �ð��뿡 ������ ��. >> W1~82\report.txt
echo �� �Ϻ� Hot Fix�� ����ǰ��ִ� OS ���α׷��̳� ���߿� Application ���α׷��� ������ �� �� �����Ƿ� ��ġ ���� �� Application ���α׷��� �����ϰ�, �ʿ��ϴٸ� OS ���� �Ǵ� Application �����Ͼ�� Ȯ�� �۾��� ��ģ �� ��ġ�� ������ ��. >> W1~82\report.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ��ġ ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-33] ��� ���α׷� ������Ʈ >> W1~82\report.txt

echo ��� ���α׷��� �ֽ� ���� ������Ʈ�� ��ġ�Ǿ� �ִ��� Ȯ�����ּ���. - [���] >> W1~82\bad\[W-33S]bad.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ��ġ ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >> W1~82\bad\[W-33S]bad.txt
echo ��� ���α׷��� �ֽ� ���� ������Ʈ�� ��ġ�Ǿ� �ִ��� Ȯ�����ּ���. - [���] >> W1~82\report.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ��ġ ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >>  W1~82\report.txt

echo ���̷κ� >> W1~82\log\[W-33]log.txt
reg query "HKLM\software\hauri" /s >> W1~82\log\[W-33]log.txt
reg query hklm\software\hauri\virobot /s | findstr /i "state" >> W1~82\log\[W-33]log.txt


echo �ȷ� V3 >> W1~82\log\[W-33]log.txt
reg query hklm\software\ahnlab /s | findstr /i "v3" | findstr /v /i "filter" >> W1~82\log\[W-33]log.txt
reg query hklm\software\ahnlab /s >> W1~82\log\[W-33]log.txt
reg query hklm\software\ahnlab /s | findstr /i "productname company autoupdateuse v3enginedate version UseSmartUpdate sysmonuse" >> W1~82\log\[W-33]log.txt

echo Ʈ���帶��ũ�� >> W1~82\log\[W-33]log.txt
reg query "hklm\software\trendmicro" /s  >> W1~82\log\[W-33]log.txt
reg query "hklm\software\trendmicro" /s | findstr /i "patterndate" >> W1~82\log\[W-33]log.txt

echo ���� ����Ʈ >> W1~82\log\[W-33]log.txt
reg query "hklm\software\microsoft\microsoft forefront" /s  >> W1~82\log\[W-33]log.txt
reg query "hklm\software\microsoft\microsoft forefront" /s | findstr /i "productupdate updatesearch" | findstr /i /v "fail loca" >> W1~82\log\[W-33]log.txt

echo Microsoft security Essentials >> W1~82\log\[W-33]log.txt
reg query "hklm\software\microsoft\microsoft Antimalware" /s  >> W1~82\log\[W-33]log.txt
reg query "hklm\software\microsoft\microsoft Antimalware" /s | findstr /i "SignaturesLastUpdated" >> W1~82\log\[W-33]log.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-34] �α��� ������ ���� �� ���� >> W1~82\report.txt

wevtutil qe Application /f:text >> W1~82\log\[W-34]ApplicationLog.txt
wevtutil qe Security /f:text >> W1~82\log\[W-34]SecurityLog.txt
wevtutil qe Setup /f:text >> W1~82\log\[W-34]SetupLog.txt
wevtutil qe System /f:text >> W1~82\log\[W-34]SystemLog.txt

echo [W-34] �α� ��Ͽ� ���� ���������� ����, �м�, ����Ʈ �ۼ� �� ���� ���� ��ġ�� �̷�� ���� �ʴ� ��� - [���] > W1~82\bad\[W-34S]bad.txt
echo ���ӱ�� ���� ���� �α�, �������α׷� �α�, �ý��� �αױ�Ͽ� ���� ���������� ����, �м�, ����Ʈ �ۼ� �� �����Ͻʽÿ�. >> W1~82\action\[W-34]action.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, �α� ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >> W1~82\action\[W-34]action.txt

echo [W-34] �α� ��Ͽ� ���� ���������� ����, �м�, ����Ʈ �ۼ� �� ���� ���� ��ġ�� �̷�� ���� �ʴ� ��� - [���] >> W1~82\report.txt
echo ���ӱ�� ���� ���� �α�, �������α׷� �α�, �ý��� �αױ�Ͽ� ���� ���������� ����, �м�, ����Ʈ �ۼ� �� �����Ͻʽÿ�. >> W1~82\report.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, �α� ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >>  W1~82\report.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-35] �������� �׼��� �� �� �ִ� ������Ʈ�� ��� >> W1~82\report.txt

sc query RemoteRegistry >> W1~82\log\[W-35]log.txt

sc query RemoteRegistry | FIND "STOPPED"
if %errorlevel% EQU 0 (
	echo [W-35] Remote Registry Service�� �����Ǿ� ���� - [��ȣ] >> W1~82\good\[W-35]good.txt
	echo [W-35] Remote Registry Service�� �����Ǿ� ���� - [��ȣ]  >> W1~82\report.txt
      SET/a LogScore = %LogScore%+12
      SET/a LogScore3 = %LogScore3%+1
)	else (
	echo [W-35] Remote Registry Service�� ��� �� - [���] >> W1~82\bad\[W-35]bad.txt
	echo [W-35] Remote Registry Service�� �����ؾ��մϴ�. >> W1~82\action\[W-35]action.txt
	echo ����-����-SERVICES.MSC �Է�-Remote Registry-�Ӽ� >> W1~82\action\[W-35]action.txt
	echo ���� ������ ��� �� ��, ���� ���¸� ������ �ٲ��ֽʽÿ�. >> W1~82\action\[W-35]action.txt

	echo [W-35] Remote Registry Service�� ��� �� - [���] >> W1~82\report.txt
	echo [W-35] Remote Registry Service�� �����ؾ��մϴ�. >> W1~82\report.txt
	echo ����-����-SERVICES.MSC �Է�-Remote Registry-�Ӽ� >> W1~82\report.txt
	echo ���� ������ ��� �� ��, ���� ���¸� ������ �ٲ��ֽʽÿ�. >> W1~82\report.txt

)

echo. >> W1~82\report.txt


echo [W-36] ��� ���α׷� ��ġ >> W1~82\report.txt

net start > W1~82\log\[W-36]log.txt

type W1~82\log\[W-36]log.txt | findstr /i "Alyac Ahnlab Hauri Symantec Trendmicro"
if %errorlevel% EQU 0 (
	echo [W-36] ������α׷��� ��ġ�Ǿ� ���� - [��ȣ] > W1~82\good\[W-36]good.txt
	echo [W-36] ������α׷��� ��ġ�Ǿ� ���� - [��ȣ] >> W1~82\report.txt
      SET/a SecureScore = %SecureScore%+12
      SET/a SecureScore3 = %SecureScore3%+1
) else (
	echo [W-36] ������α׷��� ��ġ�Ǿ� ���� ���� - [���] > W1~82\bad\[W-36]bad.txt 
	echo [W-36] ���� ����ڸ� ���� ���̷��� ��� ���α׷��� �ݵ�� ��ġ�Ͽ��� �ϵ��� �� >> W1~82\action\[W-36]action.txt

	echo [W-36] ������α׷��� ��ġ�Ǿ� ���� ���� - [���] >> W1~82\report.txt
	echo [W-36] ���� ����ڸ� ���� ���̷��� ��� ���α׷��� �ݵ�� ��ġ�Ͽ��� �ϵ��� �� >> W1~82\report.txt

)

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-37] SAM ���� ���� ���� ���� >> W1~82\report.txt
echo.

icacls C:\windows\system32\config\SAM > W1~82\log\[W-37]log.txt

icacls C:\windows\system32\config\SAM > log.txt
type log.txt | findstr /I "%COMPUTERNAME% Everyone" 
if errorlevel 1 goto W37G
if not errorlevel 1 goto W37B

:W37G
echo [W-37] SAM ���� ���ٱ��ѿ� Administrator, System �׷츸 ��� �������� �����Ǿ� �ִ� ��� - [��ȣ] > W1~82\good\[W-37]good.txt
echo [W-37] SAM ���� ���ٱ��ѿ� Administrator, System �׷츸 ��� �������� �����Ǿ� �ִ� ��� - [��ȣ] >> W1~82\report.txt
SET/a SecureScore = %SecureScore%+12
SET/a SecureScore3 = %SecureScore3%+1

goto W37

:W37B
echo [W-37] SAM ���� ���ٱ��ѿ� Administrator, System �׷� �� �ٸ� �׷쿡 ������ �����Ǿ� �ִ� ��� - [���] > W1~82\bad\[W-37]bad.txt 
echo [W-37] c:windows\system32\config\SAM �Ӽ� ���� ã�� ���� >> W1~82\action\[W-37]action.txt
echo [W-37] Administrator, System �׷� �� �ٸ� ����� �� �׷���� ���� >> W1~82\action\[W-37]action.txt

echo [W-37] SAM ���� ���ٱ��ѿ� Administrator, System �׷� �� �ٸ� �׷쿡 ������ �����Ǿ� �ִ� ��� - [���] >> W1~82\report.txt 
echo [W-37] c:windows\system32\config\SAM �Ӽ� ���� ã�� ���� >> W1~82\report.txt
echo [W-37] Administrator, System �׷� �� �ٸ� ����� �� �׷���� ���� >> W1~82\report.txt
goto W37

:W37
del log.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-38] ȭ�� ��ȣ�� ���� >> W1~82\report.txt
SET/a W38S=0

echo [ȭ�麸ȣ�� Ȱ��ȭ ����]
reg query "HKCU\Control Panel\Desktop" /v ScreenSaveActive > ScreenSaveActive.txt
reg query "HKCU\Control Panel\Desktop" /v ScreenSaveActive > W1~82\log\[W-38-1]log.txt
for /f "tokens=3" %%a in (ScreenSaveActive.txt) do set ScreenSaveActive=%%a 
if %ScreenSaveActive% EQU 0 (
	echo [W-38-1] ȭ�� ��ȣ�Ⱑ �������� ���� ��� - [���] >> W1~82\bad\[W-38]bad.txt 
	echo [W-38-1] ������-���÷���-ȭ�麸ȣ�� ���� ã�� ����-ȭ�� ��ȣ�� Ȱ��ȭ >> W1~82\action\[W-38-1]action.txt

	echo [W-38-1] ȭ�� ��ȣ�Ⱑ �������� ���� ��� - [���] >> W1~82\report.txt
	echo [W-38-1] ������-���÷���-ȭ�麸ȣ�� ���� ã�� ����-ȭ�� ��ȣ�� Ȱ��ȭ >> W1~82\report.txt

) else (
	echo [W-38-1] ȭ�� ��ȣ�Ⱑ ������ ��� - [��ȣ] >> W1~82\good\[W-38]good.txt
	echo [W-38-1] ȭ�� ��ȣ�Ⱑ ������ ��� - [��ȣ] >> W1~82\report.txt
	SET/a SecureScore = %SecureScore%+4
	SET/a W38S=1
)

del ScreenSaveActive.txt

echo [W-38-1] ȭ�� ��ȣ�Ⱑ �������� ���� ��� (������Ʈ������ ������Ʈ ���� ���� �� �ֱ⿡ ���� ����) - [���] > W1~82\bad\[W-38S]bad.txt 
echo [W-38-1] ������-���÷���-ȭ�麸ȣ�� ���� ã�� ����-ȭ�� ��ȣ�� Ȱ��ȭ >> W1~82\action\[W-38-1]action.txt

echo [W-38-1] ȭ�� ��ȣ�Ⱑ �������� ���� ��� (������Ʈ������ ������Ʈ ���� ���� �� �ֱ⿡ ���� ����) - [���] >> W1~82\report.txt
echo [W-38-1] ������-���÷���-ȭ�麸ȣ�� ���� ã�� ����-ȭ�� ��ȣ�� Ȱ��ȭ >> W1~82\report.txt

echo [ȭ�� ��ȣ�� ��ȣȭ ��� ����] >> W1~82\report.txt
reg query "HKCU\Control Panel\Desktop" /v ScreenSaverIsSecure > ScreenSaverIsSecure.txt
reg query "HKCU\Control Panel\Desktop" /v ScreenSaverIsSecure > W1~82\log\[W-38-2]log.txt
for /f "tokens=3" %%a in (ScreenSaverIsSecure.txt) do set ScreenSaverIsSecure=%%a
if %ScreenSaverIsSecure% EQU 0 (
	echo [W-38-2] ȭ�� ��ȣ�� ��ȣȭ�� ������� ���� ���  - [���] >> W1~82\bad\[W-38]bad.txt 
	echo [W-38-2] ������-���÷���-ȭ�麸ȣ�� ���� ã�� ����-ȭ�� ��ȣ�� ��ȣ��� ���� >> W1~82\action\[W-38-2]action.txt

	echo [W-38-2] ȭ�� ��ȣ�� ��ȣȭ�� ������� ���� ���  - [���] >> W1~82\report.txt
	echo [W-38-2] ������-���÷���-ȭ�麸ȣ�� ���� ã�� ����-ȭ�� ��ȣ�� ��ȣ��� ���� >> W1~82\report.txt
) else (
	echo [W-38-2] ȭ�� ��ȣ�� ��ȣȭ�� ����ϴ� ��� - [��ȣ] >> W1~82\good\[W-38]good.txt
	echo [W-38-2] ȭ�� ��ȣ�� ��ȣȭ�� ����ϴ� ��� - [��ȣ] >> W1~82\report.txt
	SET/a SecureScore = %SecureScore%+4
	SET/a W38S=1
)

del ScreenSaverIsSecure.txt


echo [ȭ�� ��ȣ�� ���ð� 10�� �̸� �� ���� ����] >> W1~82\report.txt

reg query "HKCU\Control Panel\Desktop" /v ScreenSaveTimeOut > ScreenSaveTimeOut.txt
reg query "HKCU\Control Panel\Desktop" /v ScreenSaveTimeOut > W1~82\log\[W-38]log.txt
for /f "tokens=3" %%a in (ScreenSaveTimeOut.txt) do set ScreenSaveTimeOut=%%a
if %ScreenSaveTimeOut% LEQ 600 (
	echo [W-38-3] ȭ�� ��ȣ�� ��� �ð��� 10�� �̸��� ������ �����Ǿ� �ִ� ��� - [��ȣ] >> W1~82\good\[W-38]good.txt
	echo [W-38-3] ȭ�� ��ȣ�� ��� �ð��� 10�� �̸��� ������ �����Ǿ� �ִ� ��� - [��ȣ] >> W1~82\report.txt
	SET/a SecureScore = %SecureScore%+4
	SET/a W38S=1
)	else (
	echo [W-38-3] ȭ�� ��ȣ�� ��� �ð��� 10���� �ʰ��� ������ �����Ǿ� �ִ� ��� - [���] >> W1~82\bad\[W-38]bad.txt 
	echo [W-38-3] ������-���÷���-ȭ�麸ȣ�� ���� ã�� ���� >> W1~82\action\[W-38-3]action.txt
	echo [W-38-3] ȭ�麸ȣ�� Ȱ��ȭ-�ٽ� ������ �� �α׿� ȭ��ǥ�� üũ-���ð� 10�� ���� >> W1~82\action\[W-38-3]action.txt

	echo [W-38-3] ȭ�� ��ȣ�� ��� �ð��� 10���� �ʰ��� ������ �����Ǿ� �ִ� ��� - [���] >> W1~82\report.txt
	echo [W-38-3] ������-���÷���-ȭ�麸ȣ�� ���� ã�� ���� >> W1~82\report.txt
	echo [W-38-3] ȭ�麸ȣ�� Ȱ��ȭ-�ٽ� ������ �� �α׿� ȭ��ǥ�� üũ-���ð� 10�� ���� >> W1~82\report.txt
)
if %W38S% EQU 1 (
	SET/a SecureScore3 = %SecureScore3%+1
)

del ScreenSaveTimeOut.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-39] �α׿� ���� �ʰ� �ý��� ���� ��� ���� >> W1~82\report.txt

reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /s | find /I "shutdownwithoutlogon" > log.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /s | find /I "shutdownwithoutlogon" > W1~82\log\[W-39]log.txt

type log.txt | find /I "shutdownwithoutlogon    REG_DWORD    0x1" >nul
if %errorlevel% EQU 0 (
	echo [W-39] �α׿� ���� �ʰ� �ý��� ���� ����� ��� �������� �����Ǿ� ���� ���� - [���] > W1~82\bad\[W-39]bad.txt 
	echo [W-39] ����-����-SECPOL.MSC-������å-���ȿɼ� ã�� ���� >> W1~82\action\[W-39]action.txt
	echo [W-39] �ý��� ���� - �α׿� ���� �ʰ� �ý��� ���� ����� ��� �������� ���� >> W1~82\action\[W-39]action.txt

	echo [W-39] �α׿� ���� �ʰ� �ý��� ���� ����� ��� �������� �����Ǿ� ���� ���� - [���] >> W1~82\report.txt 
	echo [W-39] ����-����-SECPOL.MSC-������å-���ȿɼ� ã�� ���� >> W1~82\report.txt
	echo [W-39] �ý��� ���� - �α׿� ���� �ʰ� �ý��� ���� ����� ��� �������� ���� >> W1~82\report.txt
  	del log.txt
) else (
	echo [W-39] �α׿� ���� �ʰ� �ý��� ���� ����� ��� �������� �����Ǿ� ���� - [��ȣ] >> W1~82\report.txt
	echo [W-39] �α׿� ���� �ʰ� �ý��� ���� ����� ��� �������� �����Ǿ� ���� - [��ȣ] >> W1~82\report.txt
	SET/a SecureScore = %SecureScore%+12
	SET/a SecureScore3 = %SecureScore3%+1
  	del log.txt
)

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-40] ��� ���α׷� ��ġ >> W1~82\report.txt

echo [W-40] ���� �ý��ۿ��� ������ �ý��� ���� ��å�� Administrators �� �ٸ� ���� �� �׷��� �����ϴ� ��� - [���] > W1~82\bad\[W-40S]bad.txt 
echo [W-40] ����-����-SECPOL.MSC-������å-����� ���� �Ҵ� ã�� ���� >> W1~82\action\[W-40S]action.txt
echo ���� �ý��ۿ��� ������ �ý��� ���� ��å�� Administrators �� �ٸ� ���� �� �׷��� ������ ��� ����ڿ� �Բ� Ȯ�� �� ���� >> W1~82\action\[W-40S]action.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >>  W1~82\report.txt

echo [W-40] ���� �ý��ۿ��� ������ �ý��� ���� ��å�� Administrators �� �ٸ� ���� �� �׷��� �����ϴ� ��� - [���] >> W1~82\report.txt
echo [W-40] ����-����-SECPOL.MSC-������å-����� ���� �Ҵ� ã�� ���� >> W1~82\report.txt
echo ���� �ý��ۿ��� ������ �ý��� ���� ��å�� Administrators �� �ٸ� ���� �� �׷��� ������ ��� ����ڿ� �Բ� Ȯ�� �� ���� >> W1~82\report.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >>  W1~82\report.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-41] ���� ���縦 �α��� �� ���� ��� ��� �ý��� ���� ���� >> W1~82\report.txt

secedit /export /cfg secpol.txt   
echo f | Xcopy "secpol.txt" "W1~82\log\[W-41]log.txt"

type secpol.txt | find /I "CrashOnAuditFail" | find "0" > NUL
if %errorlevel% EQU 0 (
	echo [W-41] "��� �� ��"���� �����Ǿ� ���� - [��ȣ] > W1~82\good\[W-41]good.txt
	echo [W-41] "��� �� ��"���� �����Ǿ� ���� - [��ȣ] >> W1~82\report.txt
      SET/a SecureScore = %SecureScore%+12
      SET/a SecureScore3 = %SecureScore3%+1
) else (
	echo [W-41] "���"���� �����Ǿ� ���� - [���] > W1~82\bad\[W-41]bad.txt
	echo [W-41] ����-����-SECPOL.MSC-������å - ���ȿɼ� ������: ���� ���縦 �α��� �� ���� ��� ��� �ý��� ���ᡱ ��å�� ����� �� �ԡ� ���� ���� >> W1~82\action\[W-41]action.txt

	echo [W-41] "���"���� �����Ǿ� ���� - [���] >> W1~82\report.txt
	echo [W-41] ����-����-SECPOL.MSC-������å - ���ȿɼ� ������: ���� ���縦 �α��� �� ���� ��� ��� �ý��� ���ᡱ ��å�� ����� �� �ԡ� ���� ���� >> W1~82\report.txt
)

del secpol.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-42] SAM ������ ������ �͸� ���� ��� �� �� >> W1~82\report.txt

secedit /export /cfg secpol.txt   
echo f | Xcopy "secpol.txt" "W1~82\log\[W-42]log.txt"

type secpol.txt | find /I "RestrictAnonymous" | find "4,1" > NUL
if %errorlevel% EQU 0 (
	echo [W-42] SAM ������ ������ �͸� ���� ��� �� �� ��å '���'���� �����Ǿ� ���� - [��ȣ] >> W1~82\good\[W-42]good.txt
	echo [W-42] SAM ������ ������ �͸� ���� ��� �� �� ��å '���'���� �����Ǿ� ���� - [��ȣ] >> W1~82\report.txt
      SET/a SecureScore = %SecureScore%+12
      SET/a SecureScore3 = %SecureScore3%+1
) else (
	echo [W-42] SAM ������ ������ �͸� ���� ��� �� �� ��å '��� �� ��'���� �����Ǿ� ���� - [���] >> W1~82\bad\[W-42]bad.txt
	echo [W-42] ����-����-SECPOL.MSC-������å - ���ȿɼ� '��Ʈ��ũ �׼��� : SAM ������ ������ �͸� ���� ��� �� ��' ���� ���� >> W1~82\action\[W-42]action.txt

	echo [W-42] SAM ������ ������ �͸� ���� ��� �� �� ��å '��� �� ��'���� �����Ǿ� ���� - [���] >> W1~82\report.txt
	echo [W-42] ����-����-SECPOL.MSC-������å - ���ȿɼ� '��Ʈ��ũ �׼��� : SAM ������ ������ �͸� ���� ��� �� ��' ���� ���� >> W1~82\report.txt

)

del secpol.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-43] IIS Exec ��ɾ� �� ȣ�� ���� >> W1~82\report.txt

reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /s > W1~82\log\[W-43]log.txt
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /s | find /I "autoadminlogon" > reg.txt

type reg.txt | findstr "1" > NUL
if %errorlevel% EQU 0 (
	echo [W-43] �ش� ������Ʈ������ 1�� - [���] > W1~82\bad\[W-43]bad.txt 
	echo ���� - ���� - REGEDIT - HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon �˻� > W1~82\action\[W-43]action.txt
	echo DWORD - AutoAdminLogon  ���� ã�� ���� 0���� �Է� >> W1~82\action\[W-43]action.txt
	echo DefaultPassword ��Ʈ���� �����Ѵٸ� ����  >> W1~82\action\[W-43]action.txt

	echo [W-43] �ش� ������Ʈ������ 1�� - [���] >> W1~82\report.txt
	echo ���� - ���� - REGEDIT - HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon �˻� >> W1~82\report.txt
	echo DWORD - AutoAdminLogon  ���� ã�� ���� 0���� �Է� >> W1~82\report.txt
	echo DefaultPassword ��Ʈ���� �����Ѵٸ� ����  >> W1~82\report.txt

) else (
	echo [W-43] ������Ʈ������ ���������ʰų� ���� 0�� - [��ȣ] > W1~82\good\[W-43]good.txt	
	echo [W-43] ������Ʈ������ ���������ʰų� ���� 0�� - [��ȣ]  >> W1~82\report.txt
      SET/a SecureScore = %SecureScore%+12
      SET/a SecureScore3 = %SecureScore3%+1
)

del reg.txt

echo.  >> W1~82\report.txt

echo.  >> W1~82\report.txt

echo [W-44] �̵��� �̵�� ���� �� ������ ���  >> W1~82\report.txt

secedit /export /cfg secpol.txt   
echo f | Xcopy "secpol.txt" "W1~82\log\[W-44]log.txt"

type secpol.txt | find /I "AllocateDASD" | find "0" 
if %errorlevel% EQU  0 (
	echo [W-44] - ��ȣ : ���̵��� �̵�� ���� �� ������ ��롱 ��å�� ��Administrator���� �Ǿ� �ִ� ��� - [��ȣ] > W1~82\good\[W-44]good.txt
	echo [W-44] - ��ȣ : ���̵��� �̵�� ���� �� ������ ��롱 ��å�� ��Administrator���� �Ǿ� �ִ� ��� - [��ȣ] >> W1~82\report.txt
      SET/a SecureScore = %SecureScore%+12
      SET/a SecureScore3 = %SecureScore3%+1
) else (
	echo [W-44] �̵��� �̵�� ���� �� ������ ��롱 ��å�� ��Administrator���� �Ǿ� ���� ���� ��� �Ǵ� ������ �ȵǾ��ִ� ��� - [���] > W1~82\bad\[W-44]bad.txt
	echo [W-44] ���� - ���� - SECPOL.MSC - ������å - ���ȿɼ�  ����ġ : �̵��� �̵�� ���� �� ������ ��롱 ��å�� ��Administrators�� �� ���� >> W1~82\action\[W-44]action.txt

	echo [W-44] �̵��� �̵�� ���� �� ������ ��롱 ��å�� ��Administrator���� �Ǿ� ���� ���� ��� �Ǵ� ������ �ȵǾ��ִ� ��� - [���] >> W1~82\report.txt
	echo [W-44] ���� - ���� - SECPOL.MSC - ������å - ���ȿɼ�  ����ġ : �̵��� �̵�� ���� �� ������ ��롱 ��å�� ��Administrators�� �� ���� >> W1~82\report.txt
)

del secpol.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-45] ��ũ���� ��ȣȭ ���� >> W1~82\report.txt

echo [W-45] "������ ��ȣ�� ���� ������ ��ȣȭ" ��å�� ���õǾ� ���� ���� ��� >> W1~82\bad\[W-45S]bad.txt
echo [W-45] ���ΰ��� ���� ������ �ݵ�� �ʿ��� ���͸��� ���ؼ��� ��ȣȭ ó�� >> W1~82\bad\[W-45S]bad.txt
echo [W-45] ���� ���� - �Ӽ� -  [�Ϲ�] �� - ��� - ��� Ư�� - �������� ��ȣ�� ���� ������ ��ȣȭ�� ����  >> W1~82\action\[W-45S]action.txt
echo [W-45] �� ���� �Ӽ� - [����] �ǿ��� �㰡�� ����� �ܿ��� ���� �� ���� ���� �Ұ��� >> W1~82\action\[W-45S]action.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >> W1~82\action\[W-45S]action.txt


echo [W-45] "������ ��ȣ�� ���� ������ ��ȣȭ" ��å�� ���õǾ� ���� ���� ��� >> W1~82\report.txt
echo [W-45] ���ΰ��� ���� ������ �ݵ�� �ʿ��� ���͸��� ���ؼ��� ��ȣȭ ó�� >> W1~82\report.txt
echo [W-45] ���� ���� - �Ӽ� -  [�Ϲ�] �� - ��� - ��� Ư�� - �������� ��ȣ�� ���� ������ ��ȣȭ�� ���� >> W1~82\report.txt
echo [W-45] �� ���� �Ӽ� - [����] �ǿ��� �㰡�� ����� �ܿ��� ���� �� ���� ���� �Ұ��� >> W1~82\report.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� ���� �׸� �������� 12���� �ο��� �ֽʽÿ�. >>  W1~82\report.txt


echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-46] Everyone ��� ������ �͸� ����ڿ��� ���� >> W1~82\report.txt

secedit /export /cfg log.txt
secedit /export /cfg \W1~82\log\[W-46]log.txt

type log.txt | find /i "EveryonIncludesAnonymous"
if %errorlevel% EQU 0 (
	echo [W-46] 'Everyone ��� ������ �͸� ����ڿ��� ����' ��å�� '�ÿ� �� ��'���� �Ǿ� �ִ� ��� - [��ȣ] > W1~82\good\[W-46]good.txt
	echo [W-46] 'Everyone ��� ������ �͸� ����ڿ��� ����' ��å�� '�ÿ� �� ��'���� �Ǿ� �ִ� ��� - [��ȣ]  >> W1~82\report.txt
	SET/a AccountScore = %AccountScore%+9
	SET/a AccountScore2 = %AccountScore2%+1

) else (
	echo [W-46] 'Everyone ��� ������ �͸� ����ڿ��� ����' ��å�� '���'���� �Ǿ� �ִ� ��� - [���] > W1~82\bad\[W-46]bad.txt
	echo [W-46] ����-����-SELPOL.MSC-������å-���ȿɼ� >> W1~82\action\[W-46]action.txt
	echo [W-46] 'Everyone ��� ������ �͸� ����ڿ��� ����' ��å�� '�ÿ� �� ��' ���� ���� >> W1~82\action\[W-46]action.txt

	echo [W-46] 'Everyone ��� ������ �͸� ����ڿ��� ����' ��å�� '���'���� �Ǿ� �ִ� ��� - [���]  >> W1~82\report.txt
	echo [W-46] ����-����-SELPOL.MSC-������å-���ȿɼ�  >> W1~82\report.txt
	echo [W-46] 'Everyone ��� ������ �͸� ����ڿ��� ����' ��å�� '�ÿ� �� ��' ���� ���� >> W1~82\report.txt

)

del log.txt


echo. >>  W1~82\report.txt

echo [W-47] ���� ��� �Ⱓ ���� >> W1~82\report.txt

net accounts | find /i "��� �Ⱓ (��):" > log.txt
net accounts | find /i "��� �Ⱓ (��):" > W1~82\log\[W-47]log.txt

type log.txt | find /i "��� �Ⱓ (��):"
for /f "tokens=4" %%a in (log.txt) do set log=%%a
if %log% LSS 60 (
	echo [W-47]  ���� ��� �Ⱓ �� ��� �Ⱓ ������� ���� �Ⱓ �� �������� ���� ��� - [���] > W1~82\bad\[W-47]bad.txt
	echo [W-47] ����-����-SELPOL.MSC-���� ��å-���� ��� ��å >> W1~82\action\[W-47]action.txt
	echo [W-47] ���� ��� �Ⱓ ���� �ð� �� ���� ��� ���� ������� ���� �� ���� ���� ��60�С� ���� >> W1~82\action\[W-47]action.txt

	echo [W-47]  ���� ��� �Ⱓ �� ��� �Ⱓ ������� ���� �Ⱓ �� �������� ���� ��� - [���] >> W1~82\report.txt
	echo [W-47] ����-����-SELPOL.MSC-���� ��å-���� ��� ��å >> W1~82\report.txt
	echo [W-47] ���� ��� �Ⱓ ���� �ð� �� ���� ��� ���� ������� ���� �� ���� ���� ��60�С� ���� >> W1~82\report.txt

) else (
	echo [W-47] ���� ��� �Ⱓ �� ������ ��� �Ⱓ ������� ���� �Ⱓ �� �����Ǿ� �ִ� ��� 60�� �̻��� ������ �����ϱ⸦ �ǰ��� - [��ȣ] > W1~82\good\[W-47]good.txt
	echo [W-47] ���� ��� �Ⱓ �� ������ ��� �Ⱓ ������� ���� �Ⱓ �� �����Ǿ� �ִ� ��� 60�� �̻��� ������ �����ϱ⸦ �ǰ��� - [��ȣ] >> W1~82\report.txt
	SET/a AccountScore = %AccountScore%+9
	SET/a AccountScore2 = %AccountScore2%+1
)

del log.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-48] �н����� ���⼺ ����

secedit /export /cfg log.txt
secedit /export /cfg W1~82\log\[W-48]log.txt

type log.txt | find /i "PasswordComplexity"
if %errorlevel% EQU 0 (
	echo [W-48] '��ȣ ���⼺�� �����ؾ� ��' ��å�� '��� �� ��'���� �Ǿ� �ִ� ��� - [���] > W1~82\bad\[W-48]bad.txt
	echo [W-48] ����-����-SECPOL.MSC-���� ��å-��ȣ ��å >> W1~82\action\[W-48]action.txt
	echo [W-48] '��ȣ�� ���⼺�� �����ؾ���'�� ������� ���� >> W1~82\action\[W-48]action.txt

	echo [W-48] '��ȣ ���⼺�� �����ؾ� ��' ��å�� '��� �� ��'���� �Ǿ� �ִ� ��� - [���] >> W1~82\report.txt
	echo [W-48] ����-����-SECPOL.MSC-���� ��å-��ȣ ��å >> W1~82\report.txt
	echo [W-48] '��ȣ�� ���⼺�� �����ؾ���'�� ������� ���� >> W1~82\report.txt

) else (
	echo [W-48] '��ȣ ���⼺�� �����ؾ� ��' ��å�� '���'���� �Ǿ� �ִ� ��� - [��ȣ] > W1~82\good\[W-48]good.txt
	echo [W-48] '��ȣ ���⼺�� �����ؾ� ��' ��å�� '���'���� �Ǿ� �ִ� ��� - [��ȣ] >> W1~82\report.txt
	SET/a AccountScore = %AccountScore%+9
	SET/a AccountScore2 = %AccountScore2%+1
)

del log.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-49] �н����� �ּ� ��ȣ ���� >> W1~82\report.txt

net accounts | find /i "�ּ� ��ȣ ����:" > log.txt
net accounts | find /i "�ּ� ��ȣ ����:" > W1~82\log\[W-49]log.txt

type log.txt | find /i "�ּ� ��ȣ ����:"
for /f "tokens=4" %%a in (log.txt) do set log=%%a
if %log% LSS 8 (
	echo [W-49] �ּ� ��ȣ ���̰� �������� �ʾҰų� 8���� �̸����� �����Ǿ� �ִ� ��� - [���] > W1~82\bad\[W-49]bad.txt
	echo [W-49] ����-����-SECPOL.MSC-������å-��ȣ��å >> W1~82\action\[W-49]action.txt
	echo [W-49] �ּ� ��ȣ ���̸� 8���ڷ� ���� >> W1~82\action\[W-49]action.txt

	echo [W-49] �ּ� ��ȣ ���̰� �������� �ʾҰų� 8���� �̸����� �����Ǿ� �ִ� ��� - [���] >> W1~82\report.txt
	echo [W-49] ����-����-SECPOL.MSC-������å-��ȣ��å >> W1~82\report.txt
	echo [W-49] �ּ� ��ȣ ���̸� 8���ڷ� ���� >> W1~82\report.txt
) else (
	echo [W-49] �ּ� ��ȣ ���̰� 8���� �̻����� �����Ǿ� �ִ� ��� - [��ȣ] > W1~82\good\[W-49]good.txt
	echo [W-49] �ּ� ��ȣ ���̰� 8���� �̻����� �����Ǿ� �ִ� ��� - [��ȣ] >> W1~82\report.txt
	SET/a AccountScore = %AccountScore%+9
	SET/a AccountScore2 = %AccountScore2%+1
)

del log.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-50] �н����� �ִ� ��� �Ⱓ >> W1~82\report.txt

net accounts | find /i "�ִ� ��ȣ ��� �Ⱓ (��):" > log.txt
net accounts | find /i "�ִ� ��ȣ ��� �Ⱓ (��):" > W1~82\log\[W-50]log.txt

type log.txt | find /i "�ִ� ��ȣ ��� �Ⱓ (��):"
for /f "tokens=6" %%a in (log.txt) do set log=%%a
if %log% GTR 90 (
	echo [W-50] �ִ� ��ȣ ��� �Ⱓ�� �������� �ʾҰų� 90���� �ʰ��ϴ� ������ ������ ��� - [���] > W1~82\bad\[W-50]bad.txt
	echo [W-50] ����-����-SECPOL.MSC-������å-��ȣ��å >> W1~82\action\[W-50]action.txt
	echo [W-50] ���ִ� ��ȣ ��� �Ⱓ���� ���� ���� ��ȣ ���� �Ⱓ�� ��90�ϡ��� ���� >> W1~82\action\[W-50]action.txt

	echo [W-50] �ִ� ��ȣ ��� �Ⱓ�� �������� �ʾҰų� 90���� �ʰ��ϴ� ������ ������ ��� - [���] >> W1~82\report.txt
	echo [W-50] ����-����-SECPOL.MSC-������å-��ȣ��å >> W1~82\report.txt
	echo [W-50] ���ִ� ��ȣ ��� �Ⱓ���� ���� ���� ��ȣ ���� �Ⱓ�� ��90�ϡ��� ���� >> W1~82\report.txt

) else (
	echo [W-50] �ִ� ��ȣ ��� �Ⱓ�� 90�� ���Ϸ� �����Ǿ� �ִ� ��� - [��ȣ] > W1~82\good\[W-50]good.txt
	echo [W-50] �ִ� ��ȣ ��� �Ⱓ�� 90�� ���Ϸ� �����Ǿ� �ִ� ��� - [��ȣ] >> W1~82\report.txt
	SET/a AccountScore = %AccountScore%+9
	SET/a AccountScore2 = %AccountScore2%+1
)

del log.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-51] �н����� �ּ� ��� �Ⱓ >> W1~82\report.txt

net accounts | find "�ּ� ��ȣ ��� �Ⱓ" > minpw.txt
net accounts | find "�ּ� ��ȣ ��� �Ⱓ" > W1~82\log\[W-51]log.txt

for /f "tokens=6" %%a in (minpw.txt) do set minpw=%%a
if %minpw% gtr 0 (
	echo [W-51] �ּ� ��ȣ ��� �Ⱓ�� 0���� ŭ - [��ȣ] >> W1~82\good\[W-51]good.txt
	echo [W-51] �ּ� ��ȣ ��� �Ⱓ�� 0���� ŭ - [��ȣ] >> W1~82\report.txt
	SET/a AccountScore = %AccountScore%+9
	SET/a AccountScore2 = %AccountScore2%+1
)	else (
	echo [W-51] �ּ� ��ȣ ��� �Ⱓ�� 0���� �����Ǿ� �ֽ��ϴ�. - [���] >> W1~82\bad\[W-51]bad.txt
	echo ����-����-SECPOL.MSC �Է�-������å-��ȣ��å >> W1~82\action\[W-51]action.txt
	echo �ּҾ�ȣ���Ⱓ�� 1�� �̻����� �����Ͻʽÿ�.�ر��� 1�ϡ� >> W1~82\action\[W-51]action.txt

	echo [W-51] �ּ� ��ȣ ��� �Ⱓ�� 0���� �����Ǿ� �ֽ��ϴ�. - [���] >> W1~82\report.txt
	echo ����-����-SECPOL.MSC �Է�-������å-��ȣ��å >> W1~82\report.txt
	echo �ּҾ�ȣ���Ⱓ�� 1�� �̻����� �����Ͻʽÿ�.�ر��� 1�ϡ� >> W1~82\report.txt
)

del minpw.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-52] ������ ����� �̸� ǥ�� �� �� >> W1~82\report.txt

secedit /export /cfg C:\value.txt
type C:\value.txt | find "DontDisplayLastUserName" > display.txt
type C:\value.txt | find "DontDisplayLastUserName" > W1~82\log\[W-52]log.txt

for /f "delims=, tokens=2" %%a in (display.txt) do set result=%%a
if %result% EQU 1 (
	echo [W-52] "������ ����� �̸� ǥ�� �� ��"�� "���"���� �����Ǿ� �ֽ��ϴ�. - [��ȣ] >> W1~82\good\[W-52]good.txt
	echo [W-52] "������ ����� �̸� ǥ�� �� ��"�� "���"���� �����Ǿ� �ֽ��ϴ�. - [��ȣ] >> W1~82\report.txt
	SET/a AccountScore = %AccountScore%+9
	SET/a AccountScore2 = %AccountScore2%+1
	del C:\value.txt
	del display.txt
)	else (
	echo [W-52] "������ ����� �̸� ǥ�� �� ��"�� "��� �� ��"���� �����Ǿ� �ֽ��ϴ�. - [���] >> W1~82\bad\[W-52]bad.txt
	echo [W-52] ����-����-SECPOL.MSC �Է�-������å-���ȿɼ� >> W1~82\action\[W-52]action.txt
	echo [W-52] "��ȭ�� �α׿�: ������ ����� �̸� ǥ�� �� ��"�� "���"���� �����Ͻʽÿ�. >>  W1~82\action\[W-52]action.txt
	echo [W-52] "������ ����� �̸� ǥ�� �� ��"�� "��� �� ��"���� �����Ǿ� �ֽ��ϴ�. - [���] >> W1~82\report.txt
	echo [W-52] ����-����-SECPOL.MSC �Է�-������å-���ȿɼ� >> W1~82\report.txt
	echo [W-52] "��ȭ�� �α׿�: ������ ����� �̸� ǥ�� �� ��"�� "���"���� �����Ͻʽÿ�. >> W1~82\report.txt

	del C:\value.txt
	del display.txt
)

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-53] ���� �α׿� ��� >> W1~82\report.txt

secedit /export /cfg C:\value.txt

type C:\value.txt | find /i "SeInteractiveLogonRight" >> W1~82\log\[W-53]log.txt
echo "���� �α׿� ��� ��å"�� Administrator, IUSR �� �ٸ� ���� �� �׷��� �����ϸ� �ȵ˴ϴ�. >> W1~82\bad\[W-53S]bad.txt
echo ����-����-SECPOL.MSC�Է�-������å-����ڱ����Ҵ�-"���� �α׿� ���"��å Ȯ�� �� Administrator, IUSR ���� ������ �����Ͻʽÿ�. >> W1~82\action\[W-53]action.txt
echo ����, �� ���� �κп��� ��ȣ�ϴٰ� �Ǵ��� �ǽŴٸ�, �����׸� �������� 9���� �ο��� �ֽʽÿ�. >> W1~82\action\[W-53]action.txt

echo "���� �α׿� ��� ��å"�� Administrator, IUSR �� �ٸ� ���� �� �׷��� �����ϸ� �ȵ˴ϴ�. >> W1~82\report.txt
echo ����-����-SECPOL.MSC�Է�-������å-����ڱ����Ҵ�-"���� �α׿� ���"��å Ȯ�� �� Administrator, IUSR ���� ������ �����Ͻʽÿ�. >> W1~82\report.txt

del C:\value.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-54] �͸� SID/�̸� ��ȯ ��� ���� >> W1~82\report.txt

secedit /export /cfg C:\inform.txt
type C:\inform.txt | find /I "LSAAnonymousNameLookup" > Anonymous.txt
type C:\inform.txt | find /I "LSAAnonymousNameLookup" > W1~82\log\[W-54]log.txt

for /f "tokens=3" %%a in (Anonymous.txt) do set result=%%a
if %result% EQU 0 (
	echo [W-54] '�͸� SID/�̸� ��ȯ ���'��å�� '��� �� ��'���� �Ǿ� ���� - [��ȣ] > W1~82\good\[W-54]good.txt
	echo [W-54] '�͸� SID/�̸� ��ȯ ���'��å�� '��� �� ��'���� �Ǿ� ���� - [��ȣ] >> W1~82\report.txt
	SET/a AccountScore = %AccountScore%+9
	SET/a AccountScore2 = %AccountScore2%+1
	del C:\inform.txt
	del Anonymous.txt
)	else (
	echo [W-54] '�͸� SID/�̸� ��ȯ ���'��å�� '���'���� �Ǿ� ���� - [���] > W1~82\bad\[W-54]bad.txt
	echo [W-54] '��Ʈ��ũ �׼���:�͸� SID/�̸� ��ȯ ���'��å�� '��� �� ��'���� �����ؾ��մϴ�. > W1~82\action\[W-54]action.txt
	echo ����-����-SECPOL.MSC�Է�-������å-���ȿɼ� > W1~82\action\[W-54]action.txt
	echo '��Ʈ��ũ �׼���: �͸� SID/�̸� ��ȯ ���' ��å�� '��� �� ��'���� ���� > W1~82\action\[W-54]action.txt

	echo [W-54] '�͸� SID/�̸� ��ȯ ���'��å�� '���'���� �Ǿ� ���� - [���] >> W1~82\report.txt
	echo [W-54] '��Ʈ��ũ �׼���:�͸� SID/�̸� ��ȯ ���'��å�� '��� �� ��'���� �����ؾ��մϴ�. >> W1~82\report.txt
	echo ����-����-SECPOL.MSC�Է�-������å-���ȿɼ� >> W1~82\report.txt
	echo '��Ʈ��ũ �׼���: �͸� SID/�̸� ��ȯ ���' ��å�� '��� �� ��'���� ���� >> W1~82\report.txt

	del C:\inform.txt
	del Anonymous.txt
)

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-55] �ֱ� ��ȣ ���

net accounts | find /I "��ȣ ���" >> uniquepw.txt
net accounts | find /I "��ȣ ���" >> W1~82\log\[W-55]log.txt

for /f "tokens=4" %%a in (uniquepw.txt) do set result=%%a
if %result% GEQ 4 (
	echo [W-55] �ֱ� ��ȣ ����� 4�� �̻����� �����Ǿ� ���� - [��ȣ] > W1~82\good\[W-55]good.txt
	echo [W-55] �ֱ� ��ȣ ����� 4�� �̻����� �����Ǿ� ���� - [��ȣ] >> W1~82\report.txt
	SET/a AccountScore = %AccountScore%+9
	SET/a AccountScore2 = %AccountScore2%+1
)	else (
	echo [W-55] �ֱ� ��ȣ ����� 4�� �̸����� �����Ǿ� ���� - [���] > W1~82\bad\[W-55]bad.txt
	echo [W-55] �ֱ� ��ȣ ����� 4�� �̻����� �����Ͻʽÿ�. >> W1~82\action\[W-55]action.txt
	echo ����-����-SECPOL.MSC�Է�-������å-��ȣ��å >> W1~82\action\[W-55]action.txt
	echo '�ֱ� ��ȣ ���'�� 4�� �̻����� ���� >> W1~82\action\[W-55]action.txt

	echo [W-55] �ֱ� ��ȣ ����� 4�� �̸����� �����Ǿ� ���� - [���] >> W1~82\report.txt
	echo [W-55] �ֱ� ��ȣ ����� 4�� �̻����� �����Ͻʽÿ�. >> W1~82\report.txt
	echo ����-����-SECPOL.MSC�Է�-������å-��ȣ��å >> W1~82\report.txt
	echo '�ֱ� ��ȣ ���'�� 4�� �̻����� ���� >> W1~82\report.txt

)

del uniquepw.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-56] �ܼ� �α׿� �� ���� �������� �� ��ȣ ��� ���� >> W1~82\report.txt

secedit /EXPORT /CFG LocalSecurityPolicy.txt

type LocalSecurityPolicy.txt | find /i "LimitBlankPasswordUse=" > W1~82/log/[W-56]log.txt

type LocalSecurityPolicy.txt | find /i "LimitBlankPasswordUse=" | find "4,1" > NUL
if %errorlevel% EQU 0 (
 echo [W-56] "�ܼ� �α׿� �� ���� �������� �� ��ȣ ��� ����" ��å�� "���"���� ������ - [��ȣ] > W1~82/good/[W-56]good.txt
 echo [W-56] "�ܼ� �α׿� �� ���� �������� �� ��ȣ ��� ����" ��å�� "���"���� ������ - [��ȣ] >> W1~82\report.txt
 SET/a AccountScore = %AccountScore%+9
 SET/a AccountScore2 = %AccountScore2%+1
)
if not %errorlevel% EQU 0 (
 echo [W-56] "�ܼ� �α׿� �� ���� �������� �� ��ȣ ��� ����" ��å�� "��� ����"���� ������ - [���] > W1~82/bad/[W-56]bad.txt
 echo [W-56] ���� - ���� - secpol.msc - ���� ��å - ���� �ɼ� >> W1~82/action/[W-56]action.txt
 echo [W-56] "���� : �ܼ� �α׿� �� ���� �������� �� ��ȣ ��� ����" ��å�� "���"���� ���� >> W1~82/action/[W-56]action.txt

 echo [W-56] "�ܼ� �α׿� �� ���� �������� �� ��ȣ ��� ����" ��å�� "��� ����"���� ������ - [���] >> W1~82\report.txt
 echo [W-56] ���� - ���� - secpol.msc - ���� ��å - ���� �ɼ� >> W1~82\report.txt
 echo [W-56] "���� : �ܼ� �α׿� �� ���� �������� �� ��ȣ ��� ����" ��å�� "���"���� ���� >> W1~82\report.txt

)

del LocalSecurityPolicy.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-57] �����͹̳� ���� ������ ����� �׷� ���� >> W1~82\report.txt

reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections > W1~82/log/[W-57]log.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections > reg.txt
type reg.txt | find /I "0x0" > NUL

if %errorlevel% EQU 0 (
 echo [W-57] "�� ��ǻ�Ϳ� ���� ���� ����" ������ "���" ���� ������ - [��ȣ] �ϳ� �߰����� ������ �ʿ��� > W1~82/bad/[W-57S]good.txt
 SET/a AccountScore = %AccountScore%+9
 SET/a AccountScore2 = %AccountScore2%+1
 echo [W-57] ������ - ����� ���� - ������ ���� �̿��� ���� ���� >> W1~82/action/[W-57]action.txt
 echo [W-57] ������ - �ý��� - ���� ���� - [����] �� - [���� ����ũ��] �޴� - "����� ����" ���� ���� ����� ���� �� Ȯ�� >> W1~82/action/[W-57]action.txt

 echo [W-57] "�� ��ǻ�Ϳ� ���� ���� ����" ������ "���" ���� ������ - [��ȣ] �ϳ� �߰����� ������ �ʿ��� >> W1~82\report.txt
 echo [W-57] ������ - ����� ���� - ������ ���� �̿��� ���� ���� >> W1~82\report.txt
 echo [W-57] ������ - �ý��� - ���� ���� - [����] �� - [���� ����ũ��] �޴� - "����� ����" ���� ���� ����� ���� �� Ȯ�� >> W1~82\report.txt

) else (
 echo [W-57] "�� ��ǻ�Ϳ� ���� ���� ����" ������ "��� �� ��" ���� ������ - [���] > W1~82/bad/[W-57S]bad.txt
 echo [W-57] ������ - ����� ���� - ������ ���� �̿��� ���� ���� >> W1~82/action/[W-57]action.txt
 echo [W-57] ������ - �ý��� - ���� ���� - [����] �� - [���� ����ũ��] �޴� >> W1~82/action/[W-57]action.txt
 echo [W-57] "�� ��ǻ�Ϳ� ���� ���� ���� ���"�� üũ - "����� ����" ���� ���� ����� ���� �� Ȯ�� >> W1~82/action/[W-57]action.txt

 echo [W-57] "�� ��ǻ�Ϳ� ���� ���� ����" ������ "��� �� ��" ���� ������ - [���] >> W1~82\report.txt
 echo [W-57] ������ - ����� ���� - ������ ���� �̿��� ���� ���� >> W1~82\report.txt
 echo [W-57] ������ - �ý��� - ���� ���� - [����] �� - [���� ����ũ��] �޴� >> W1~82\report.txt
 echo [W-57] "�� ��ǻ�Ϳ� ���� ���� ���� ���"�� üũ - "����� ����" ���� ���� ����� ���� �� Ȯ�� >> W1~82\report.txt

)

del reg.txt

echo.>> W1~82\report.txt

echo. >> W1~82\report.txt
echo [W-58] �͹̳� ���� ��ȣȭ ���� ���� >> W1~82\report.txt

reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MinEncryptionLevel > W1~82/log/[W-58]log.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MinEncryptionLevel > reg.txt
type reg.txt | findstr "0x0 0x1"

if %errorlevel% EQU 0 (
 echo [W-58] �͹̳� ���񽺸� ����ϰ�, ��ȣȭ ������ "����"���� ������ - [���] > W1~82/bad/[W-58]bad.txt
 echo [W-58] ���� - ���� - REGEDIT >> W1~82/action/[W-58]action.txt
 echo "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" >> W1~82/action/[W-58]action.txt
 echo "MinEncryptionLevel" ���� "2(�߰�)"�̻����� ���� >> W1~82/action/[W-58]action.txt

 echo [W-58] �͹̳� ���񽺸� ����ϰ�, ��ȣȭ ������ "����"���� ������ - [���] >> W1~82\report.txt
 echo [W-58] ���� - ���� - REGEDIT >> W1~82\report.txt
 echo "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" >> W1~82\report.txt
 echo "MinEncryptionLevel" ���� "2(�߰�)"�̻����� ���� >> W1~82\report.txt
)
if not %errorlevel% EQU 0 (
 echo [W-58] �͹̳� ���񽺸� ������� �ʰų�, ��� �� ��ȣȭ ������ "Ŭ���̾�Ʈ�� ȣȯ����(�߰�)�̻�"���� ������ - [��ȣ] > W1~82/good/[W-58]good.txt
 echo [W-58] �͹̳� ���񽺸� ������� �ʰų�, ��� �� ��ȣȭ ������ "Ŭ���̾�Ʈ�� ȣȯ����(�߰�)�̻�"���� ������ - [��ȣ] >> W1~82\report.txt
 SET/a ServiceScore = %ServiceScore%+9
 SET/a ServiceScore2 = %ServiceScore2%+1

)

del reg.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-59] IIS ������ ���� ���� >> W1~82\report.txt

type C:\Windows\System32\inetsrv\config\applicationHost.config > W1~82\log\[W-59]log.txt
type W1~82\log\[W-59]log.txt | find /i "httpErrors errorMode" > iisweb.txt

type iisweb.txt | find /i "custom"
if %errorlevel% EQU 0 (
	echo [W-59] �� ���� ���� �������� ������ �����Ǿ� �ִ� ��� - [��ȣ] > W1~82\good\[W-59]good.txt
	echo [W-59] �� ���� ���� �������� ������ �����Ǿ� �ִ� ��� - [��ȣ] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+9
	SET/a ServiceScore2 = %ServiceScore2%+1
) else (
	echo [W-59] �� ���� ���� �������� ������ �������� �ʾ� ���� �߻� �� �߿� ���� �� ����Ǵ� ���- [���] > W1~82\bad\[W-59]bad.txt
	echo [W-59] ������- ���� ����- IIS[���ͳ� ���� ����] ������- �ش� �� ����Ʈ- [���� ������] - [�۾�] �ǿ��� [��� ���� ����] - ���� ���� �߻� �� ���� ��ȯ �׸��� ����� ���� ���� �������� ���� > W1~82\action\[W-59]action.txt

	echo [W-59] �� ���� ���� �������� ������ �������� �ʾ� ���� �߻� �� �߿� ���� �� ����Ǵ� ���- [���] >> W1~82\report.txt
	echo [W-59] ������- ���� ����- IIS[���ͳ� ���� ����] ������- �ش� �� ����Ʈ- [���� ������] - [�۾�] �ǿ��� [��� ���� ����] - ���� ���� �߻� �� ���� ��ȯ �׸��� ����� ���� ���� �������� ���� >> W1~82\report.txt

)

del iisweb.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-60] SNMP ���� �������� >> W1~82\report.txt
net start | findstr /I "snmp"  > W1~82\log\[W-60]log.txt
net start | find /I "SNMP Service" > nul

if errorlevel 1 goto W60G
if not errorlevel 1 goto W60B

:W60G
echo [W-60] SNMP ���񽺸� ������� �ʴ� ��� - [��ȣ] > W1~82\good\[W-60]good.txt
echo [W-60] SNMP ���񽺸� ������� �ʴ� ��� - [��ȣ] >> W1~82\report.txt
SET/a ServiceScore = %ServiceScore%+9
SET/a ServiceScore2 = %ServiceScore2%+1

:W60B
echo [W-60] SNMP ���񽺸� ����ϴ� ��� - [���] > W1~82\bad\[W-60]bad.txt
echo [W-60] ����-����-SERVICES.MSC-SNMP Service �Ӽ�-"���� ����"�� "��� ����"���� ����-SNMP ���� ���� >> W1~82\action\[W-60]action.txt
echo [W-60] SNMP ���񽺸� ����ϴ� ��� - [���] >> W1~82\report.txt
echo [W-60] ����-����-SERVICES.MSC-SNMP Service �Ӽ�-"���� ����"�� "��� ����"���� ����-SNMP ���� ���� >> W1~82\report.txt


del log.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-61] SNMP ���� Ŀ�´�Ƽ��Ʈ���� ���⼺ ���� >> W1~82\report.txt

reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" > log.txt
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" > W1~82\log\[W-61]log.txt

type log.txt | findstr /I "public private" >nul
if errorlevel 1 goto W61G
if not errorlevel 1 goto W61B

:W61G
echo [W-61] SNMP ���񽺸� ������� �ʰų�, Community String�� public, private�� �ƴ� ��� - [��ȣ] > W1~82\good\[W-61]good.txt
echo [W-61] SNMP ���񽺸� ������� �ʰų�, Community String�� public, private�� �ƴ� ��� - [��ȣ] >> W1~82\report.txt
SET/a ServiceScore = %ServiceScore%+9
SET/a ServiceScore2 = %ServiceScore2%+1
:W61B
echo [W-61] SNMP ���񽺸� ����ϸ�, Community String�� public, private�� ���  - [���] > W1~82\bad\[W-61]bad.txt
echo [W-61] ����-����-SERVICES.MSC-SNMP Service �Ӽ�-����-[���� Ʈ�� ������] �� üũ�ڽ� ���� �Ǵ� [�޾Ƶ��� Ŀ�´�Ƽ �̸�]���� public, private ���� >> W1~82\action\[W-61]action.txt

echo [W-61] SNMP ���񽺸� ����ϸ�, Community String�� public, private�� ���  - [���] >> W1~82\report.txt
echo [W-61] ����-����-SERVICES.MSC-SNMP Service �Ӽ�-����-[���� Ʈ�� ������] �� üũ�ڽ� ���� �Ǵ� [�޾Ƶ��� Ŀ�´�Ƽ �̸�]���� public, private ���� >> W1~82\report.txt

del log.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-62] SNMP Access control ���� >> W1~82\report.txt
SET/a W62S=0
SET/a W62S1=0
SET/a W62S2=0

reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters" | find /i "EnableAuthenticationTraps" > inform.txt
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters" >> W1~82\log\[W-62]log.txt
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" > inform2.txt
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" >> W1~82\log\[W-62]log.txt

type inform.txt | find /i "0x1"
if %errorlevel% equ 0 (
	echo [W-62] "���� Ʈ�� ������"�� üũ�� �Ǿ��ֽ��ϴ� >> W1~82\good\[W-62]good.txt
	echo [W-62] "���� Ʈ�� ������"�� üũ�� �Ǿ��ֽ��ϴ� >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+4
	SET/a W62S=1
	SET/a W62S1=1

)	else (
	echo [W-62] "���� Ʈ�� ������"�� üũ�� �Ǿ����� �ʽ��ϴ� >> W1~82\bad\[W-62]bad.txt
	echo [W-62] ^<���� Ʈ�� ������^> >> W1~82\action\[W-62]action.txt
	echo ����-����-SERVICES.MSC �Է�-SNMP Service-�Ӽ�-����-"���� Ʈ�� ������"�� üũ���ּ��� >> W1~82\action\[W-62]action.txt

	echo [W-62] "���� Ʈ�� ������"�� üũ�� �Ǿ����� �ʽ��ϴ� >> W1~82\report.txt
	echo [W-62] ^<���� Ʈ�� ������^> >> W1~82\report.txt
	echo ����-����-SERVICES.MSC �Է�-SNMP Service-�Ӽ�-����-"���� Ʈ�� ������"�� üũ���ּ��� >> W1~82\report.txt

)

type inform2.txt | find /i "1"
if %errorlevel% equ 0 (
	echo [W-62] "Ư�� ȣ��Ʈ�κ��� SNMP ��Ŷ �޾Ƶ��̱�"�� �����Ǿ� �ֽ��ϴ� >> W1~82\good\[W-62]good.txt
	echo [W-62] "Ư�� ȣ��Ʈ�κ��� SNMP ��Ŷ �޾Ƶ��̱�"�� �����Ǿ� �ֽ��ϴ� >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+4
	SET/a W62S=1
	SET/a W62S2=1
)	else (
	echo [W-62] "��� ȣ��Ʈ�κ��� SNMP ��Ŷ �޾Ƶ��̱�"�� �����Ǿ� �ֽ��ϴ� >> W1~82\bad\[W-62]bad.txt
	echo [W-62] ^<Ư�� ȣ��Ʈ�κ��� SNMP ��Ŷ �޾Ƶ��̱� ������^> >> W1~82\action\[W-62]action.txt
	echo ����-����-SERVICES.MSC �Է�-SNMP Service-�Ӽ�-���� >> W1~82\action\[W-62]action.txt
	echo "���� ȣ��Ʈ�κ��� SNMP ��Ŷ �޾Ƶ��̱�" üũ �� �ؿ� �߰� ��ư�� ���� ȣ��Ʈ�� �������ּ��� >> W1~82\action\[W-62]action.txt

	echo [W-62] "��� ȣ��Ʈ�κ��� SNMP ��Ŷ �޾Ƶ��̱�"�� �����Ǿ� �ֽ��ϴ� >> W1~82\report.txt
	echo [W-62] ^<Ư�� ȣ��Ʈ�κ��� SNMP ��Ŷ �޾Ƶ��̱� ������^> >> W1~82\report.txt
	echo ����-����-SERVICES.MSC �Է�-SNMP Service-�Ӽ�-���� >> W1~82\report.txt
	echo "���� ȣ��Ʈ�κ��� SNMP ��Ŷ �޾Ƶ��̱�" üũ �� �ؿ� �߰� ��ư�� ���� ȣ��Ʈ�� �������ּ��� >> W1~82\report.txt
)

if %W62S% EQU 1 (
	SET/a ServiceScore2 = %ServiceScore2%+1
)
if %W62S1% EQU 1 (
	if %W62S2% EQU 1 (
		SET/a ServiceScore = %ServiceScore%+1
	)
)
del inform.txt
del inform2.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-63] DNS ���� �������� >> W1~82\report.txt

net start > W1~82\log\[W-63]log.txt

net start | find "DNS Server" 
if %errorlevel% EQU 1 (
	echo [W-63] DNS ���񽺸� ������� �ʰų�, ���� ������Ʈ�� "����"���� �����Ǿ� �ִ� ��� - [��ȣ] > W1~82\good\[W-63]good.txt
	echo [W-63] DNS ���񽺸� ������� �ʰų�, ���� ������Ʈ�� "����"���� �����Ǿ� �ִ� ��� - [��ȣ] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+9
	SET/a ServiceScore2 = %ServiceScore2%+1
) else (
	echo [W-63] DNS ���񽺸� ����ϸ�, ���� ������Ʈ�� �����Ǿ� �ִ� ��� - [���] > W1~82\bad\[W-63]bad.txt
	echo [W-63] ����-����-DNSMGMT.MSC-�� ��ȸ ����-�ش� ����-�Ӽ�-�Ϲ�-���� ������Ʈ-���� ���� >> W1~82\action\[W-63]action.txt

	echo [W-63] DNS ���񽺸� ����ϸ�, ���� ������Ʈ�� �����Ǿ� �ִ� ��� - [���] >> W1~82\report.txt
	echo [W-63] ����-����-DNSMGMT.MSC-�� ��ȸ ����-�ش� ����-�Ӽ�-�Ϲ�-���� ������Ʈ-���� ���� >> W1~82\report.txt
)

del log.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo  [W-64] HTTP/FTP/SMTP ��� ���� >> W1~82\report.txt

type C:\Windows\System32\inetsrv\config\applicationHost.config > W1~82\log\[W-79]log.txt
type C:\Windows\System32\inetsrv\config\applicationHost.config > logsu.txt
type logsu.txt | findstr /i "suppressDefaultBanner" | find "true"
if %errorlevel% EQU 0 (
	echo [W-64] FTP, ���� �� ��� ������ ������ �ʴ� ��� - [��ȣ] > W1~82\good\[W-64]good.txt
	echo [W-64] FTP, ���� �� ��� ������ ������ �ʴ� ��� - [��ȣ] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+6
	SET/a ServiceScore1 = %ServiceScore1%+1
) else (
	echo [W-64] FTP ���� �� ��ʸ� ����ϴ� ��� - [���] > W1~82\bad\[W-64]bad.txt
	echo [W-64] IIS ���ͳ� ���� ���� ������ - FTP �޽��� - �⺻ ��� ����� ���� > W1~82\action\[W-64]action.txt

	echo [W-64] FTP ���� �� ��ʸ� ����ϴ� ��� - [���] >> W1~82\report.txt
	echo [W-64] IIS ���ͳ� ���� ���� ������ - FTP �޽��� - �⺻ ��� ����� ���� >> W1~82\report.txt
)

del logsu.txt

echo [W-64S] HTTP ��� Ȯ�� �ʿ� > W1~82\bad\[W-64S]bad.txt
echo [W-64S] SMTP ��� Ȯ�� �ʿ� >> W1~82\bad\[W-64S]bad.txt
echo [W-64S] HTTP ��� Ȯ�� �ʿ� >> W1~82\report.txt
echo [W-64S] SMTP ��� Ȯ�� �ʿ� >> W1~82\report.txt

echo Microsoft �ٿ�ε� ���Ϳ��� URL Rewrite �ٿ�ε� �� ��ġ https://www.iis.net/downloads/microsoft/url-rewrite >> W1~82\action\[W-64S]action.txt
echo. > W1~82\action\[W-64S]action.txt
echo ������ - �������� - IIS[���ͳ� ���� ����] ������ - �ش� �� ����Ʈ - [URL ���ۼ�]  >> W1~82\action\[W-64S]action.txt
echo �۾� �� - [���� �� ���� - ���� ���� ����...] >> W1~82\action\[W-64S]action.txt
echo �۾� �� - [�߰�...]- ���� ���� �߰�- ���� ���� �̸�: RESPONSE_SERVER  >>W1~82\action\[W-64S]action.txt
echo [URL ���ۼ�] - �۾� �� - [��Ģ �߰�...] - �ƿ��ٿ�� ��Ģ - �� ��Ģ  >> W1~82\action\[W-64S]action.txt
echo �̸�, �˻� ����, ���� �̸�, ���� ���� - ����- �̸�(N): Remove Server - �˻� ����: ���� ����- ���� �̸�: RESPONSE_SERVER- ���� T: .*  >> W1~82\action\[W-64S]action.txt
echo. >> W1~82\action\[W-64S]action.txt
echo. >> W1~82\action\[W-64S]action.txt

echo Microsoft �ٿ�ε� ���Ϳ��� URL Rewrite �ٿ�ε� �� ��ġ https://www.iis.net/downloads/microsoft/url-rewrite >> W1~82\report.txt
echo. >> W1~82\report.txt
echo ������ - �������� - IIS[���ͳ� ���� ����] ������ - �ش� �� ����Ʈ - [URL ���ۼ�]  >> W1~82\report.txt
echo �۾� �� - [���� �� ���� - ���� ���� ����...] >> W1~82\report.txt
echo �۾� �� - [�߰�...]- ���� ���� �߰�- ���� ���� �̸�: RESPONSE_SERVER  >> W1~82\report.txt
echo [URL ���ۼ�] - �۾� �� - [��Ģ �߰�...] - �ƿ��ٿ�� ��Ģ - �� ��Ģ  >> W1~82\report.txt
echo �̸�, �˻� ����, ���� �̸�, ���� ���� - ����- �̸�(N): Remove Server - �˻� ����: ���� ����- ���� �̸�: RESPONSE_SERVER- ���� T: .*  >> W1~82\report.txt
echo. >> W1~82\report.txt
echo. >> W1~82\report.txt

echo ���� - ���� - cmd - adsutil.vbs ������ �ִ� ���͸��� �̵�- ��ɾ�: cd C:\inetpub\AdminScripts- adsutil.vbs�� ����ϱ� ���� ���� �����ڿ��� ���� �߰� �ʿ� >> W1~82\action\[W-64S]action.txt
echo [�� ����IIS-���� ����- IIS 6 ���� ȣȯ��- IIS 6 ��ũ���� ����] ��ġ �ʿ� >> W1~82\action\[W-64S]action.txt
echo IIS���� ���� ���� SMTP ���� ��� Ȯ��- ��ɾ�: cscript adsutil.vbs enum /p smtpsvc >> W1~82\action\[W-64S]action.txt
echo SMTP ���񽺿� connectresponse �Ӽ� ������ ��� ���� ����- ��ɾ�: cscript adsutil.vbs set smtpsvc/1/connectresponse ��Banner Text >> W1~82\action\[W-64S]action.txt
echo SMTP ���� �����- ��ɾ�: net stop smtpsvc ����- ��ɾ�: net start smtpsvc ���� >> W1~82\action\[W-64S]action.txt

echo ���� - ���� - cmd - adsutil.vbs ������ �ִ� ���͸��� �̵�- ��ɾ�: cd C:\inetpub\AdminScripts- adsutil.vbs�� ����ϱ� ���� ���� �����ڿ��� ���� �߰� �ʿ� >> W1~82\report.txt
echo [�� ����IIS-���� ����- IIS 6 ���� ȣȯ��- IIS 6 ��ũ���� ����] ��ġ �ʿ� >> W1~82\report.txt
echo IIS���� ���� ���� SMTP ���� ��� Ȯ��- ��ɾ�: cscript adsutil.vbs enum /p smtpsvc >> W1~82\report.txt
echo SMTP ���񽺿� connectresponse �Ӽ� ������ ��� ���� ����- ��ɾ�: cscript adsutil.vbs set smtpsvc/1/connectresponse ��Banner Text >> W1~82\report.txt
echo SMTP ���� �����- ��ɾ�: net stop smtpsvc ����- ��ɾ�: net start smtpsvc ���� >> W1~82\report.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-65] Telnet ���� ���� >> W1~82\report.txt

net start > W1~82\log\[W-65]log.txt
type W1~82\log\[W-65]log.txt | find /I "Telnet"
if %errorlevel% EQU 1 (
	echo [W-65] Telnet Service �� ������ - [��ȣ] >> W1~82\good\[W-65]good.txt
	echo [W-65] Telnet Service �� ������ - [��ȣ] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+9
	SET/a ServiceScore2 = %ServiceScore2%+1
	goto W65END
) else (
	echo [W-65] Telnet Service ������ - [���] >> W1~82\bad\[W-65]bad.txt
	echo [W-65] Telnet Service ������ - [���] >> W1~82\report.txt
	goto W65-1
)

:W65-1
echo [W-65] Telnet ���� ����
tlntadmn config | find "���� ��Ŀ����" > W1~82\log\[W-65-1]log.txt
tlntadmn config | find "���� ��Ŀ����" > logt.txt
type logt.txt | find /i "password"
if %errorlevel% EQU 0 (
	echo [W-65-1] passwd ���� ��� ����� - [���] >> W1~82\bad\[W-65]bad.txt
	echo [W-65-1] ����- ����- cmd- tlntadmn config >> W1~82\action\[W-65]action.txt
	echo [W-65-1] tlntadmn config sec = +NTLM -passwd [�� �Է��Ͽ� passwd ���� ����� �����ϰ� NTLM ���� ��ĸ� ���] >> W1~82\action\[W-65]action.txt
	echo [W-65-1] ���ʿ� �� �ش� ���� ���� - ����-  ���� - SERVICES.MSC - Telnet - �Ӽ� [�Ϲ�] �ǿ��� "���� ����"�� "��� �� ��"���� ������ �� Telnet ���� ���� >> W1~82\action\[W-65]action.txt
	echo [W-65-1] passwd ���� ��� ����� - [���] >> W1~82\report.txt
	echo [W-65-1] ����- ����- cmd- tlntadmn config >> W1~82\report.txt
	echo [W-65-1] tlntadmn config sec = +NTLM -passwd [�� �Է��Ͽ� passwd ���� ����� �����ϰ� NTLM ���� ��ĸ� ���] >> W1~82\report.txt
	echo [W-65-1] ���ʿ� �� �ش� ���� ���� - ����-  ���� - SERVICES.MSC - Telnet - �Ӽ� [�Ϲ�] �ǿ��� "���� ����"�� "��� �� ��"���� ������ �� Telnet ���� ���� >> W1~82\report.txt
) else (
	echo [W-65] ���ʿ� �� �ش� ���� ���� - ���� - ���� - SERVICES.MSC - Telnet = �Ӽ� [�Ϲ�] �ǿ��� "���� ����"�� "��� �� ��"���� ������ �� Telnet ���� ���� >> W1~82\action\[W-65]action.txt
	echo [W-65] ���ʿ� �� �ش� ���� ���� - ���� - ���� - SERVICES.MSC - Telnet = �Ӽ� [�Ϲ�] �ǿ��� "���� ����"�� "��� �� ��"���� ������ �� Telnet ���� ���� >> W1~82\report.txt
)

:W65END
del logt.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo  [W-66] ���ʿ��� ODBC/OLE-DB ������ �ҽ��� ����̺� ���� >> W1~82\report.txt

echo [W-66] ������� �ʴ� ���ʿ��� ODBC ������ �ҽ� ���� > W1~82\bad\[W-66S]bad.txt
echo [W-66] ���� - ���� - ������ - ���� ���� - ODBC ������ ���� - �ý��� DSN - �ش� ����̺� Ŭ�� > W1~82\bad\[W-66S]action.txt
echo ������� �ʴ� ������ �ҽ� ���� >> W1~82\bad\[W-66S]action.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� �׸� �������� 9���� �ο��� �ֽʽÿ�. >> W1~82\report.txt

echo [W-66] ������� �ʴ� ���ʿ��� ODBC ������ �ҽ� ���� >> W1~82\report.txt
echo [W-66] ���� - ���� - ������ - ���� ���� - ODBC ������ ���� - �ý��� DSN - �ش� ����̺� Ŭ�� >> W1~82\report.txt
echo ������� �ʴ� ������ �ҽ� ���� >> W1~82\report.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� �׸� �������� 9���� �ο��� �ֽʽÿ�. >> W1~82\report.txt


echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-67] ���� ���� �� ����� �׷� ���� >> W1~82\report.txt

reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" > W1~82\log\[W-67]log.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" | find /I "MaxIdleTime" > 67log.txt
type 67log.txt | find /I "MaxIdleTime" | find /I 1800000
if %errorlevel% EQU 0 (
	echo �������� �� Timeout ���� ������ ����Ǿ� 30������ ������ ��� - [��ȣ] > W1~82\good\[W-67]good.txt
	echo �������� �� Timeout ���� ������ ����Ǿ� 30������ ������ ��� - [��ȣ] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+9
	SET/a ServiceScore2 = %ServiceScore2%+1
) else (
	echo  �������� �� Timeout ���� ������ �������� ���� ��� - [���] > W1~82\bad\[W-67]bad.txt
	echo  ���� - ���� - GPEDIT.MSC[���� �׷� ��å ������] >> W1~82\action\[W-67]action.txt
	echo  ��ǻ�� ���� - ���� ���ø� - Windows ���� ��� - �͹̳� ���� - ���� ����ũ�鼼�� ȣ��Ʈ - ���� �ð� ���� >> W1~82\action\[W-67]action.txt
	echo  [Ȱ�� �������� ���� �͹̳� ���� ���ǿ� �ð����� ����] - [���� ���� ����]�� 30������ ���� >> W1~82\action\[W-67]action.txt

	echo  �������� �� Timeout ���� ������ �������� ���� ��� - [���] >> W1~82\report.txt
	echo  ���� - ���� - GPEDIT.MSC[���� �׷� ��å ������] >> W1~82\report.txt
	echo  ��ǻ�� ���� - ���� ���ø� - Windows ���� ��� - �͹̳� ���� - ���� ����ũ�鼼�� ȣ��Ʈ - ���� �ð� ���� >> W1~82\report.txt
	echo  [Ȱ�� �������� ���� �͹̳� ���� ���ǿ� �ð����� ����] - [���� ���� ����]�� 30������ ���� >> W1~82\report.txt
)

del 67log.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-68] ����� �۾��� �ǽɽ����� ����� ��ϵǾ� �ִ��� ���� >> W1~82\report.txt

schtasks > W1~82\log\[W-68]log.txt
echo ���ʿ��� ��ɾ ���� �� �ֱ����� ���� �۾��� ���� ���θ� ���� ���� �ʿ� -[���] > W1~82\bad\[W-68S]bad.txt
echo GUI Ȯ�� ��� - ������ - �������� - �۾� �����ٷ����� Ȯ�� ��ϵ� ���� �۾��� �����Ͽ� �󼼳��� Ȯ�� ���ʿ��� ���� ���� �� ����   >> W1~82\action\[W-68]action.txt
echo CLI�� ��� [W-68]log.txt ����   >> W1~82\action\[W-68]action.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� �׸� �������� 9���� �ο��� �ֽʽÿ�. >> W1~82\action\[W-68]action.txt

echo ���ʿ��� ��ɾ ���� �� �ֱ����� ���� �۾��� ���� ���θ� ���� ���� �ʿ� -[���] >> W1~82\report.txt
echo GUI Ȯ�� ��� - ������ - �������� - �۾� �����ٷ����� Ȯ�� ��ϵ� ���� �۾��� �����Ͽ� �󼼳��� Ȯ�� ���ʿ��� ���� ���� �� ���� >> W1~82\report.txt
echo CLI�� ��� [W-68]log.txt ���� >> W1~82\report.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� �׸� �������� 9���� �ο��� �ֽʽÿ�. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-69] ��å�� ���� �ý��� �α� ���� >> W1~82\report.txt
SET/a W69S=0

secedit /export /cfg LocalSecurityPolicy.txt
type LocalSecurityPolicy.txt | findstr /i "AuditSystemEvents AuditLogonEvents AuditObjectAccess AuditPrivilegeUse AuditPolicyChange AuditAccountManage AuditProcessTracking AuditDSAccess AuditAccountLogon" > log.txt
type LocalSecurityPolicy.txt | findstr /i "AuditSystemEvents AuditLogonEvents AuditObjectAccess AuditPrivilegeUse AuditPolicyChange AuditAccountManage AuditProcessTracking AuditDSAccess AuditAccountLogon" > W1~82/log/[W-69]log.txt
type log.txt | findstr /i "AuditSystemEvents" > SystemEvents.txt
type log.txt | findstr /i "AuditLogonEvents" > LogonEvents.txt
type log.txt | findstr /i "AuditObjectAccess" > ObjectAccess.txt
type log.txt | findstr /i "AuditPrivilegeUse" > PrivilegeUse.txt
type log.txt | findstr /i "AuditPolicyChange" > PolicyChange.txt
type log.txt | findstr /i "AuditAccountManage" > AccountManage.txt
type log.txt | findstr /i "AuditProcessTracking" > ProcessTracking.txt
type log.txt | findstr /i "AuditDSAccess" > DSAccess.txt
type log.txt | findstr /i "AuditAccountLogon" > AccountLogon.txt


for /f "tokens=3" %%a in (SystemEvents.txt) do set SystemEvents=%%a
if %SystemEvents% == 3 (
 echo [W-69] �ý��� �̺�Ʈ ���� - [��ȣ] >> W1~82/good/[W-69]good.txt
 echo [W-69] �ý��� �̺�Ʈ ���� - [��ȣ] >> W1~82\report.txt
 SET/a PatchScore = %PatchScore%+1
 SET/a W69S=1
) else (
 echo [W-69] �ý��� �̺�Ʈ ���� - [���] >> W1~82/bad/[W-69]bad.txt
 echo [W-69] �ý��� �̺�Ʈ ���� - [���] ==================--- >> W1~82/action/[W-69]action.txt
 echo [W-69] ���� - ���� - SECPOL.MSC - ���� ��å - ���� ��å >> W1~82/action/[W-69]action.txt
 echo [W-69] "�ý��� �̺�Ʈ ����" �׸� "����,����"�� ���� >> W1~82/action/[W-69]action.txt

 echo [W-69] �ý��� �̺�Ʈ ���� - [���] >> W1~82\report.txt
 echo [W-69] ���� - ���� - SECPOL.MSC - ���� ��å - ���� ��å >> W1~82\report.txt
 echo [W-69] "�ý��� �̺�Ʈ ����" �׸� "����,����"�� ���� >> W1~82\report.txt

)
for /f "tokens=3" %%a in (LogonEvents.txt) do set LogonEvents=%%a
if %LogonEvents% == 3 (
 echo [W-69] �α׿� �̺�Ʈ ���� - [��ȣ] >> W1~82/good/[W-69]good.txt
 echo [W-69] �α׿� �̺�Ʈ ���� - [��ȣ] >> W1~82\report.txt
 SET/a PatchScore = %PatchScore%+1
 SET/a W69S=1
) else (
 echo [W-69] �α׿� �̺�Ʈ ���� - [���] >> W1~82/bad/[W-69]bad.txt
 echo [W-69] �α׿� �̺�Ʈ ���� - [���] ==================-- >> W1~82/action/[W-69]action.txt
 echo [W-69] ���� - ���� - SECPOL.MSC - ���� ��å - ���� ��å >> W1~82/action/[W-69]action.txt
 echo [W-69] "�α׿� �̺�Ʈ ����" �׸� "����,����"�� ���� >> W1~82/action/[W-69]action.txt

 echo [W-69] �α׿� �̺�Ʈ ���� - [���] >> W1~82\report.txt
 echo [W-69] ���� - ���� - SECPOL.MSC - ���� ��å - ���� ��å >> W1~82\report.txt
 echo [W-69] "�α׿� �̺�Ʈ ����" �׸� "����,����"�� ���� >> W1~82\report.txt
)
for /f "tokens=3" %%a in (ObjectAccess.txt) do set ObjectAccess=%%a
if %ObjectAccess% == 0 (
 echo [W-69] ��ü �׼��� ���� - [��ȣ] >> W1~82/good/[W-69]good.txt
 echo [W-69] ��ü �׼��� ���� - [��ȣ] >> W1~82\report.txt
 SET/a PatchScore = %PatchScore%+1
 SET/a W69S=1
) else (
 echo [W-69] ��ü �׼��� ���� - [���] >> W1~82/bad/[W-69]bad.txt
 echo [W-69] ��ü �׼��� ���� - [���] ==================---- >> W1~82/action/[W-69]action.txt
 echo [W-69] ���� - ���� - SECPOL.MSC - ���� ��å - ���� ��å >> W1~82/action/[W-69]action.txt
 echo [W-69] "��ü �׼��� ����" �׸� "���� �� ��"���� ���� >> W1~82/action/[W-69]action.txt

 echo [W-69] ��ü �׼��� ���� - [���] >> W1~82\report.txt
 echo [W-69] ���� - ���� - SECPOL.MSC - ���� ��å - ���� ��å >> W1~82\report.txt
 echo [W-69] "��ü �׼��� ����" �׸� "���� �� ��"���� ���� >> W1~82\report.txt
)
for /f "tokens=3" %%a in (PrivilegeUse.txt) do set PrivilegeUse=%%a
if %PrivilegeUse% == 0 (
 echo [W-69] ���� ��� ���� - [��ȣ] >> W1~82/good/[W-69]good.txt
 echo [W-69] ���� ��� ���� - [��ȣ] >> W1~82\report.txt
 SET/a PatchScore = %PatchScore%+1
 SET/a W69S=1
) else (
 echo [W-69] ���� ��� ���� - [���] >> W1~82/bad/[W-69]bad.txt
 echo [W-69] ���� ��� ���� - [���] ======================== >> W1~82/action/[W-69]action.txt
 echo [W-69] ���� - ���� - SECPOL.MSC - ���� ��å - ���� ��å >> W1~82/action/[W-69]action.txt
 echo [W-69] "���� ��� ����" �׸� "���� �� ��"���� ���� >> W1~82/action/[W-69]action.txt

 echo [W-69] ���� ��� ���� - [���] >> W1~82\report.txt
 echo [W-69] ���� - ���� - SECPOL.MSC - ���� ��å - ���� ��å >> W1~82\report.txt
 echo [W-69] "���� ��� ����" �׸� "���� �� ��"���� ���� >> W1~82\report.txt
)
for /f "tokens=3" %%a in (PolicyChange.txt) do set PolicyChange=%%a
if %PolicyChange% == 1 (
 echo [W-69] ��å ���� ���� - [��ȣ] >> W1~82/good/[W-69]good.txt
 echo [W-69] ��å ���� ���� - [��ȣ] >> W1~82\report.txt
 SET/a PatchScore = %PatchScore%+1
 SET/a W69S=1
) else (
 echo [W-69] ��å ���� ���� - [���] >> W1~82/bad/[W-69]bad.txt
 echo [W-69] ��å ���� ���� - [���] ======================== >> W1~82/action/[W-69]action.txt
 echo [W-69] ���� - ���� - SECPOL.MSC - ���� ��å - ���� ��å >> W1~82/action/[W-69]action.txt
 echo [W-69] "��å ���� ����" �׸� "����"���� ���� >> W1~82/action/[W-69]action.txt

 echo [W-69] ��å ���� ���� - [���] >> W1~82\report.txt
 echo [W-69] ���� - ���� - SECPOL.MSC - ���� ��å - ���� ��å >> W1~82\report.txt
 echo [W-69] "��å ���� ����" �׸� "����"���� ���� >> W1~82\report.txt
)
for /f "tokens=3" %%a in (AccountManage.txt) do set AccountManage=%%a
if %AccountManage% == 1 (
 echo [W-69] ���� ���� ���� - [��ȣ] >> W1~82/good/[W-69]good.txt
 echo [W-69] ���� ���� ���� - [��ȣ] >> W1~82\report.txt
 SET/a PatchScore = %PatchScore%+1
 SET/a W69S=1

) else (
 echo [W-69] ���� ���� ���� - [���] >> W1~82/bad/[W-69]bad.txt
 echo [W-69] ���� ���� ���� - [���] ======================== >> W1~82/action/[W-69]action.txt
 echo [W-69] ���� - ���� - SECPOL.MSC - ���� ��å - ���� ��å >> W1~82/action/[W-69]action.txt
 echo [W-69] "���� ���� ����" �׸� "����"���� ���� >> W1~82/action/[W-69]action.txt

 echo [W-69] ���� ���� ���� - [���] >> W1~82\report.txt
 echo [W-69] ���� - ���� - SECPOL.MSC - ���� ��å - ���� ��å >> W1~82\report.txt
 echo [W-69] "���� ���� ����" �׸� "����"���� ���� >> W1~82\report.txt
)
for /f "tokens=3" %%a in (ProcessTracking.txt) do set ProcessTracking=%%a
if %ProcessTracking% == 0 (
 echo [W-69] ���μ��� ���� ���� - [��ȣ] >> W1~82/good/[W-69]good.txt
 echo [W-69] ���μ��� ���� ���� - [��ȣ] >> W1~82\report.txt
 SET/a PatchScore = %PatchScore%+1
 SET/a W69S=1
) else (
 echo [W-69] ���μ��� ���� ���� - [���] >> W1~82/bad/[W-69]bad.txt
 echo [W-69] ���μ��� ���� ���� - [���] ==================-- >> W1~82/action/[W-69]action.txt
 echo [W-69] ���� - ���� - SECPOL.MSC - ���� ��å - ���� ��å >> W1~82/action/[W-69]action.txt
 echo [W-69] "���μ��� ���� ����" �׸� "���� �� ��"���� ���� >> W1~82/action/[W-69]action.txt

 echo [W-69] ���μ��� ���� ���� - [���] >> W1~82\report.txt
 echo [W-69] ���� - ���� - SECPOL.MSC - ���� ��å - ���� ��å >> W1~82\report.txt
 echo [W-69] "���μ��� ���� ����" �׸� "���� �� ��"���� ���� >> W1~82\report.txt
)
for /f "tokens=3" %%a in (DSAccess.txt) do set DSAccess=%%a
if %DSAccess% == 1 (
 echo [W-69] ���丮 ���� �׼��� ���� - [��ȣ] >> W1~82/good/[W-69]good.txt
 echo [W-69] ���丮 ���� �׼��� ���� - [��ȣ] >> W1~82\report.txt
 SET/a PatchScore = %PatchScore%+1
 SET/a W69S=1
) else (
 echo [W-69] ���丮 ���� �׼��� ���� - [���] >> W1~82/bad/[W-69]bad.txt
 echo [W-69] ���丮 ���� �׼��� ���� - [���] ======----- >> W1~82/action/[W-69]action.txt
 echo [W-69] ���� - ���� - SECPOL.MSC - ���� ��å - ���� ��å >> W1~82/action/[W-69]action.txt
 echo [W-69] "���丮 ���� �׼��� ����" �׸� "����"���� ���� >> W1~82/action/[W-69]action.txt

 echo [W-69] ���丮 ���� �׼��� ���� - [���] >> W1~82\report.txt
 echo [W-69] ���� - ���� - SECPOL.MSC - ���� ��å - ���� ��å >> W1~82\report.txt
 echo [W-69] "���丮 ���� �׼��� ����" �׸� "����"���� ���� >> W1~82\report.txt
)
for /f "tokens=3" %%a in (AccountLogon.txt) do set AccountLogon=%%a
if %AccountLogon% == 1 (
 echo [W-69] ���� �α׿� �̺�Ʈ ���� - [��ȣ] >> W1~82/good/[W-69]good.txt
 echo [W-69] ���� �α׿� �̺�Ʈ ���� - [��ȣ] >> W1~82\report.txt
 SET/a PatchScore = %PatchScore%+1
 SET/a W69S=1
) else (
 echo [W-69] ���� �α׿� �̺�Ʈ ���� - [���] >> W1~82/bad/[W-69]bad.txt
 echo [W-69] ���� �α׿� �̺�Ʈ ���� - [���] ============--- >> W1~82/action/[W-69]action.txt
 echo [W-69] ���� - ���� - SECPOL.MSC - ���� ��å - ���� ��å >> W1~82/action/[W-69]action.txt
 echo [W-69] "���� �α׿� �̺�Ʈ ����" �׸� "����"���� ���� >> W1~82/action/[W-69]action.txt

 echo [W-69] ���� �α׿� �̺�Ʈ ���� - [���] >> W1~82\report.txt
 echo [W-69] ���� - ���� - SECPOL.MSC - ���� ��å - ���� ��å >> W1~82\report.txt
 echo [W-69] "���� �α׿� �̺�Ʈ ����" �׸� "����"���� ���� >> W1~82\report.txt
)

del SystemEvents.txt LogonEvents.txt ObjectAccess.txt PrivilegeUse.txt PolicyChange.txt
del AccountManage.txt ProcessTracking.txt DSAccess.txt AccountLogon.txt
del log.txt LocalSecurityPolicy.txt
if %W69S% EQU 1 (
	SET/a PatchScore2 = %PatchScore2%+1
)

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-70] �̺�Ʈ �α� ���� ���� >> W1~82\report.txt\
SET/a W70S=0

wevtutil gl security > W1~82\log\[W-70]log.txt
wevtutil gl security > test.txt
type test.txt | find /i "maxSize" > size.txt
type test.txt | find /i "retention" >> oldlog.txt
type test.txt | find /i "autoBackup" >> oldlog.txt

for /f "tokens=2" %%a in (size.txt) do set size=%%a
if %size% gtr 10480000 (
	echo [W-70] �ִ� �α� ũ�� "10,240KB �̻�"���� �����Ͽ����ϴ� - [��ȣ] >> W1~82\good\[W-70]good.txt
	echo [W-70] Default�� �ƴ� �ٸ� �α״� ����Ȯ���ؾ��մϴ� >> W1~82\bad\[W-70S]bad.txt
	echo [W-70] ^<Default�� �ƴ� �ٸ� �α� Ȯ�ι�^> >> W1~82\action\[W-70S]action.txt
	echo ����-����-EVENTVWR.MSC�Է�-�ش�α�-�Ӽ�-�Ϲ� >> W1~82\action\[W-70S]action.txt
	echo �ִ� �α� ũ�⸦ 10,240 �̻����� �������ּ��� >> W1~82\action\[W-70S]action.txt

	echo [W-70] �ִ� �α� ũ�� "10,240KB �̻�"���� �����Ͽ����ϴ� - [��ȣ] >> W1~82\report.txt
	echo [W-70] Default�� �ƴ� �ٸ� �α״� ����Ȯ���ؾ��մϴ� >> W1~82\report.txt
	echo [W-70] ^<Default�� �ƴ� �ٸ� �α� Ȯ�ι�^> >> W1~82\report.txt
	echo ����-����-EVENTVWR.MSC�Է�-�ش�α�-�Ӽ�-�Ϲ� >> W1~82\report.txt
	echo �ִ� �α� ũ�⸦ 10,240 �̻����� �������ּ��� >> W1~82\report.txt

	SET/a LogScore = %LogScore%+3
	SET/a W70S=1
) else (
	echo [W-70] �ִ� �α� ũ�� "10,240KB �̸�"���� �����Ͽ����ϴ� - [���] >> W1~82\bad\[W-70]bad.txt
	echo [W-70] �ִ� �α� ũ�� ���� >> W1~82\action\[W-70]action.txt
	echo ����-����-EVENTVWR.MSC�Է�-�ش�α�-�Ӽ�-�Ϲ� >> W1~82\action\[W-70]action.txt
	echo �ִ� �α� ũ�⸦ 10,240 �̻����� �������ּ��� >> W1~82\action\[W-70]action.txt
	echo [W-70] Default�� �ƴ� �ٸ� �α״� ����Ȯ���ؾ��մϴ� >> W1~82\bad\[W-70S]bad.txt
	echo [W-70] ^<Default�� �ƴ� �ٸ� �α� Ȯ�ι�^> >> W1~82\action\[W-70S]action.txt
	echo ����-����-EVENTVWR.MSC�Է�-�ش�α�-�Ӽ�-�Ϲ� >> W1~82\action\[W-70S]action.txt
	echo �ִ� �α� ũ�⸦ 10,240 �̻����� �������ּ��� >> W1~82\action\[W-70S]action.txt

	echo [W-70] �ִ� �α� ũ�� "10,240KB �̸�"���� �����Ͽ����ϴ� - [���] >> W1~82\report.txt
	echo [W-70] �ִ� �α� ũ�� ���� >> W1~82\report.txt
	echo ����-����-EVENTVWR.MSC�Է�-�ش�α�-�Ӽ�-�Ϲ� >> W1~82\report.txt
	echo �ִ� �α� ũ�⸦ 10,240 �̻����� �������ּ��� >> W1~82\report.txt
	echo [W-70] Default�� �ƴ� �ٸ� �α״� ����Ȯ���ؾ��մϴ� >> W1~82\report.txt
	echo [W-70] ^<Default�� �ƴ� �ٸ� �α� Ȯ�ι�^> >> W1~82\report.txt
	echo ����-����-EVENTVWR.MSC�Է�-�ش�α�-�Ӽ�-�Ϲ� >> W1~82\report.txt
	echo �ִ� �α� ũ�⸦ 10,240 �̻����� �������ּ��� >> W1~82\report.txt

)

type oldlog.txt | find /i "true"
if %errorlevel% equ 0 (
	echo [W-70]"�ʿ��� ��� �̺�Ʈ �����"�� üũ�� �ȵǾ��ֽ��ϴ� - [���] >> W1~82\bad\[W-70]bad.txt
	echo [W-70] �ִ� �α� ũ�� ���� �� ���� >> W1~82\action\[W-70]action.txt
	echo ����-����-EVENTVWR.MSC�Է�-�ش�α�-�Ӽ�-�Ϲ� >> W1~82\action\[W-70]action.txt
	echo "�ʿ��� ��� �̺�Ʈ �����"�� üũ���ּ���. >> W1~82\action\[W-70]action.txt
	echo [W-70]"�ʿ��� ��� �̺�Ʈ �����"�� üũ���ּ���. >> W1~82\action\[W-70S]action.txt

	echo [W-70]"�ʿ��� ��� �̺�Ʈ �����"�� üũ�� �ȵǾ��ֽ��ϴ� - [���] >> W1~82\report.txt
	echo [W-70] �ִ� �α� ũ�� ���� �� ���� >> W1~82\report.txt
	echo ����-����-EVENTVWR.MSC�Է�-�ش�α�-�Ӽ�-�Ϲ� >> W1~82\report.txt
	echo "�ʿ��� ��� �̺�Ʈ �����"�� üũ���ּ���. >> W1~82\report.txt
	echo [W-70]"�ʿ��� ��� �̺�Ʈ �����"�� üũ���ּ���. >> W1~82\report.txt

) else (
	echo [W-70] "�ʿ��� ��� �̺�Ʈ �����"�� üũ�Ǿ� �ֽ��ϴ� - [��ȣ] >> W1~82\good\[W-70]good.txt
	echo [W-70] "�ʿ��� ��� �̺�Ʈ �����"�� üũ���ּ���. >> W1~82\action\[W-70S]action.txt	

	echo [W-70] "�ʿ��� ��� �̺�Ʈ �����"�� üũ�Ǿ� �ֽ��ϴ� - [��ȣ] >> W1~82\report.txt
	echo [W-70] "�ʿ��� ��� �̺�Ʈ �����"�� üũ���ּ���. >> W1~82\report.txt	

	SET/a LogScore = %LogScore%+3
	SET/a W70S=1
)

if %W70S% EQU 1 (
	SET/a LogScore1 = %LogScore1%+1
)


del oldlog.txt
del test.txt
del size.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-71] ���ݿ��� �̺�Ʈ �α� ���� ���� ���� >> W1~82\report.txt

icacls C:\Windows\System32\LogFiles > inform.txt
icacls C:\Windows\System32\LogFiles > W1~82\log\[W-71]log.txt

type inform.txt | find /i "everyone"
if %errorlevel% equ 0 (
	echo [W-71] �α� ���丮�� ���ٱ��ѿ� Everyone ������ �ֽ��ϴ� - [���] >> W1~82\bad\[W-71]bad.txt
	echo [W-71] Ž����-�α� ���丮-�Ӽ�-���� >> W1~82\action\[W-71]action.txt
	echo Everyone ���� >> W1~82\action\[W-71]action.txt

	echo [W-71] �α� ���丮�� ���ٱ��ѿ� Everyone ������ �ֽ��ϴ� - [���] >> W1~82\report.txt
	echo [W-71] Ž����-�α� ���丮-�Ӽ�-���� >> W1~82\report.txt
	echo Everyone ���� >> W1~82\report.txt
) else (
	echo �α� ���丮�� ���ٱ��ѿ� Everyone ������ �ֽ��ϴ� - [��ȣ] >> W1~82\good\[W-71]good.txt
	echo �α� ���丮�� ���ٱ��ѿ� Everyone ������ �ֽ��ϴ� - [��ȣ] >> W1~82\report.txt
	SET/a LogScore = %LogScore%+9
	SET/a LogScore2 = %LogScore2%+1
)

del inform.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-72] DoS ���� ��� ������Ʈ�� ���� >> W1~82\report.txt
SET/a W72S=0

reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters > dos.txt
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters > W1~82\log\[W-72]log.txt
type dos.txt | findstr /i "SynAttackProtect EnableDeadGWDetect KeepAliveTime NoNameReleaseOnDemand" >> inform.txt

type inform.txt | find /i "SynAttackProtect" | findstr /i "1 2"
if %errorlevel% equ 0 (
	echo [W-72] SynAttackProtect ��ȣ >> W1~82\good\[W-72]good.txt
	echo [W-72] SynAttackProtect ��ȣ >> W1~82\report.txt
	SET/a SecureScore = %SecureScore%+3
	SET/a W72S=1
) else (
	echo [W-72] SynAttackProtect ��� >> W1~82\bad\[W-72]bad.txt
	echo [W-72] SynAttackProtect ��� >> W1~82\report.txt
	echo [W-72] ����-����-REGEDIT�Է� >> W1~82\action\[W-72]action.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters �˻� >> W1~82\action\[W-72]action.txt
	echo ������Ʈ�� �̸� : SynAttackProtect / ������Ʈ�� �� ���� : REG_DWORD / ��ȿ ���� : 0, 1, 2 / ���� ���� �� : 1 �Ǵ� 2�� ���� >> W1~82\action\[W-72]action.txt
	echo ���� ������Ʈ���� ������ �߰����ּ��� >> W1~82\action\[W-72]action.txt

	echo [W-72] ����-����-REGEDIT�Է� >> W1~82\report.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters �˻� >> W1~82\report.txt
	echo ������Ʈ�� �̸� : SynAttackProtect / ������Ʈ�� �� ���� : REG_DWORD / ��ȿ ���� : 0, 1, 2 / ���� ���� �� : 1 �Ǵ� 2�� ���� >> W1~82\report.txt
	echo ���� ������Ʈ���� ������ �߰����ּ��� >> W1~82\report.txt
)
type inform.txt | find /i "EnableDeadGWDetect" | findstr /i "0"
if %errorlevel% equ 0 (
	echo [W-72] EnableDeadGWDetect ��ȣ >> W1~82\good\[W-72]good.txt
	echo [W-72] EnableDeadGWDetect ��ȣ >> W1~82\report.txt
	SET/a SecureScore = %SecureScore%+3
	SET/a W72S=1
) else (
	echo [W-72] EnableDeadGWDetect ��� >> W1~82\bad\[W-72]bad.txt
	echo [W-72] EnableDeadGWDetect ��� >> W1~82\report.txt
	echo [W-72] ����-����-REGEDIT�Է� >> W1~82\action\[W-72]action.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters �˻� >> W1~82\action\[W-72]action.txt
	echo ������Ʈ�� �̸� : EnableDeadGWDetect, ������Ʈ�� �� ���� : REG_DWORD, ��ȿ ���� : 0, 1 (False, True),  >> W1~82\action\[W-72]action.txt
	echo ���� ���� �� : 0���� (False)�� �����ϼ���. >> W1~82\action\[W-72]action.txt
	echo ���� ������Ʈ���� ������ �߰����ּ��� >> W1~82\action\[W-72]action.txt
	echo [W-72] ����-����-REGEDIT�Է� >> W1~82\report.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters �˻� >> W1~82\report.txt
	echo ������Ʈ�� �̸� : EnableDeadGWDetect, ������Ʈ�� �� ���� : REG_DWORD, ��ȿ ���� : 0, 1 (False, True) >> W1~82\report.txt
	echo ���� ���� �� : 0���� (False)�� �����ϼ���. >> W1~82\report.txt
	echo ���� ������Ʈ���� ������ �߰����ּ��� >> W1~82\report.txt
)
type inform.txt | find /i "KeepAliveTime" | findstr /i "300000"
if %errorlevel% equ 0 (
	echo [W-72] KeepAliveTime ��ȣ >> W1~82\good\[W-72]good.txt
	echo [W-72] KeepAliveTime ��ȣ >> W1~82\report.txt
	SET/a SecureScore = %SecureScore%+3
	SET/a W72S=1
) else (
	echo [W-72] KeepAliveTime ��� >> W1~82\bad\[W-72]bad.txt
	echo [W-72] KeepAliveTime ��� >> W1~82\report.txt
	echo [W-72] ����-����-REGEDIT�Է� >> W1~82\action\[W-72]action.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters �˻� >> W1~82\action\[W-72]action.txt
	echo ������Ʈ�� �̸� : KeepAliveTime , ������Ʈ�� �� ���� : REG_DWORD >> W1~82\action\[W-72]action.txt
	echo ��ȿ ���� : 1 : 0xFFFFFFFF, >> W1~82\action\[W-72]action.txt
	echo ���� ���� �� : 300,000 �����ϼ���. >> W1~82\action\[W-72]action.txt
	echo ���� ������Ʈ���� ������ �߰����ּ��� >> W1~82\action\[W-72]action.txt
	echo [W-72] ����-����-REGEDIT�Է� >> W1~82\report.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters �˻� >> W1~82\report.txt
	echo ������Ʈ�� �̸� : KeepAliveTime / ������Ʈ�� �� ���� : REG_DWORD >> W1~82\report.txt
	echo ��ȿ ���� : 1 - 0xFFFFFFFF / ���� ���� �� : 300,000���� >> W1~82\report.txt
	echo ���� ������Ʈ���� ������ �߰����ּ��� >> W1~82\report.txt
)
type inform.txt | find /i "NoNameReleaseOnDemand" | findstr /i "1"
if %errorlevel% equ 0 (
	echo [W-72] NoNameReleaseOnDemand ��ȣ >> W1~82\good\[W-72]good.txt
	echo [W-72] NoNameReleaseOnDemand ��ȣ >> W1~82\report.txt
	SET/a SecureScore = %SecureScore%+3
	SET/a W72S=1
) else (
	echo [W-72] NoNameReleaseOnDemand ��� >> W1~82\bad\[W-72]bad.txt
	echo [W-72] NoNameReleaseOnDemand ��� >> W1~82\report.txt
	echo [W-72] ����-����-REGEDIT�Է� >> W1~82\action\[W-72]action.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters �˻� >> W1~82\action\[W-72]action.txt
	echo ������Ʈ�� �̸� : NoNameReleaseOnDemand / ������Ʈ�� �� ���� : REG_DWORD >> W1~82\action\[W-72]action.txt
	echo ��ȿ ���� : 0, 1 (False, True) >> W1~82\action\[W-72]action.txt
	echo ���� ���� �� : 1 (True)���� ���� >> W1~82\action\[W-72]action.txt
	echo ���� ������Ʈ���� ������ �߰����ּ��� >> W1~82\action\[W-72]action.txt
	echo [W-72] ����-����-REGEDIT�Է� >> W1~82\report.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters �˻� >> W1~82\report.txt
	echo ��ȿ ���� : 0, 1 (False, True) / >> W1~82\report.txt
	echo ���� ���� �� : 1 (True)�� ���� >> W1~82\report.txt
	echo ���� ������Ʈ���� ������ �߰����ּ��� >> W1~82\report.txt	
)
del dos.txt
del inform.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-73] ����ڰ� ������ ����̹��� ��ġ�� �� ���� �� >> W1~82\report.txt

reg query "HKLM\SYSTEM\ControlSet001\Control\Print\Providers\LanMan Print Services\Servers" > log.txt
reg query "HKLM\SYSTEM\ControlSet001\Control\Print\Providers\LanMan Print Services\Servers" > W1~82\log\[W-73]log.txt
type log.txt | find /I "AddPrinterDrivers" > log1.txt

type log1.txt | find /I "0x0" >nul
if %errorlevel% EQU 0 (
	echo [W-73] ����ڰ� ������ ����̹��� ��ġ�� �� ���� �� ��å�� ��� ������ ��� - [���] > W1~82\bad\[W-73]bad.txt 
	echo [W-73] ����-����-SECPOL.MSC-������å-���ȿɼ�-[��ġ] ����ڰ� ������ ����̹��� ��ġ�� �� ������ - ��å�� ������� ���� >> W1~82\action\[W-73]action.txt

	echo [W-73] ����ڰ� ������ ����̹��� ��ġ�� �� ���� �� ��å�� ��� ������ ��� - [���] >> W1~82\report.txt 
	echo [W-73] ����-����-SECPOL.MSC-������å-���ȿɼ�-[��ġ] ����ڰ� ������ ����̹��� ��ġ�� �� ������ - ��å�� ������� ���� >> W1~82\report.txt
) else (
	echo [W-73] ����ڰ� ������ ����̹��� ��ġ�� �� ���� �� ��å�� ������� �����Ǿ� �ִ� ��� - [��ȣ] > W1~82\good\[W-73]good.txt
	echo [W-73] ����ڰ� ������ ����̹��� ��ġ�� �� ���� �� ��å�� ������� �����Ǿ� �ִ� ��� - [��ȣ] >> W1~82\report.txt
      SET/a SecureScore = %SecureScore%+9
      SET/a SecureScore2 = %SecureScore2%+1
)

del log.txt
del log1.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-74] ���� ������ �ߴ��ϱ� ���� �ʿ��� ���޽ð� >> W1~82\report.txt
SET/a W74S=0
SET/a W74S1=0
SET/a W74S2=0

reg query "HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Parameters" > log.txt
reg query "HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Parameters" > W1~82\log\[W-74]log.txt

type log.txt | find /I "enableforcedlogoff    REG_DWORD    0x0" >nul
if %errorlevel% EQU 0 (
	echo [W-74-1] �α׿� �ð��� ����Ǹ� Ŭ���̾�Ʈ ���� ���� ��å�� ��� �������� �����Ǿ� ���� ��� - [���] >> W1~82\bad\[W-74]bad.txt 
	echo [W-74-1] ����-����-SECPOL.MSC-������å-���ȿɼ�-�α׿� �ð��� ����Ǹ� Ŭ���̾�Ʈ ���� ����- ��å�� ��� �������� ���� >> W1~82\action\[W-74]action.txt

	echo [W-74-1] �α׿� �ð��� ����Ǹ� Ŭ���̾�Ʈ ���� ���� ��å�� ��� �������� �����Ǿ� ���� ��� - [���] >> W1~82\report.txt
	echo [W-74-1] ����-����-SECPOL.MSC-������å-���ȿɼ�-�α׿� �ð��� ����Ǹ� Ŭ���̾�Ʈ ���� ����- ��å�� ��� �������� ���� >> W1~82\report.txt
) else (
	echo [W-74-1] �α׿� �ð��� ����Ǹ� Ŭ���̾�Ʈ ���� ���� ��å�� ������� �����Ǿ� �ִ� ��� - [��ȣ] >> W1~82\good\[W-74]good.txt
	echo [W-74-1] �α׿� �ð��� ����Ǹ� Ŭ���̾�Ʈ ���� ���� ��å�� ������� �����Ǿ� �ִ� ��� - [��ȣ] >> W1~82\report.txt
	SET/a SecureScore = %SecureScore%+4
	SET/a W74S=1
	SET/a W74S1=1
)

type log.txt | find /I "autodisconnect    REG_DWORD    0xffffffff" >nul
if %errorlevel% EQU 0 (
	echo [W-74-2] ���� ������ �ߴ��ϱ� ���� �ʿ��� ���� �ð� ��å�� 15������ �����Ǿ� ���� ���� ��� - [���] >> W1~82\bad\[W-74]bad.txt 
	echo [W-74-2] ����-����-SECPOL.MSC-������å-���ȿɼ�-���� ������ �ߴ��ϱ� ���� �ʿ��� ���� �ð�-��å�� 15������ ���� >> W1~82\action\[W-74]action.txt

	echo [W-74-2] ���� ������ �ߴ��ϱ� ���� �ʿ��� ���� �ð� ��å�� 15������ �����Ǿ� ���� ���� ��� - [���] >> W1~82\report.txt
	echo [W-74-2] ����-����-SECPOL.MSC-������å-���ȿɼ�-���� ������ �ߴ��ϱ� ���� �ʿ��� ���� �ð�-��å�� 15������ ���� >> W1~82\report.txt
) else (
       goto W74C
)

:W74C
type log.txt | find /I "autodisconnect    REG_DWORD    0xf" >nul
if %errorlevel% EQU 0 (
	echo [W-74-2] ���� ������ �ߴ��ϱ� ���� �ʿ��� ���� �ð� ��å�� 15������ �����Ǿ� �ִ� ��� - [��ȣ] >> W1~82\good\[W-74]good.txt
	echo [W-74-2] ���� ������ �ߴ��ϱ� ���� �ʿ��� ���� �ð� ��å�� 15������ �����Ǿ� �ִ� ��� - [��ȣ] >> W1~82\report.txt
	SET/a SecureScore = %SecureScore%+4
	SET/a W74S=1
	SET/a W74S2=1
) else (
	echo [W-74-2] ���� ������ �ߴ��ϱ� ���� �ʿ��� ���� �ð� ��å�� 15������ �����Ǿ� ���� ���� ��� - [���] >> W1~82\bad\[W-74]bad.txt 
	echo [W-74-2] ����-����-SECPOL.MSC-������å-���ȿɼ�-���� ������ �ߴ��ϱ� ���� �ʿ��� ���� �ð�-��å�� 15������ ���� >> W1~82\action\[W-74]action.txt

	echo [W-74-2] ���� ������ �ߴ��ϱ� ���� �ʿ��� ���� �ð� ��å�� 15������ �����Ǿ� ���� ���� ��� - [���] >> W1~82\report.txt
	echo [W-74-2] ����-����-SECPOL.MSC-������å-���ȿɼ�-���� ������ �ߴ��ϱ� ���� �ʿ��� ���� �ð�-��å�� 15������ ���� >> W1~82\report.txt
)

if %W74S% EQU 1 (
	SET/a SecureScore2 = %SecureScore2%+1
)
if %W74S1% EQU 1 (
	if %W74S2% EQU 1 (
		SET/a SecureScore = %SecureScore%+1
	)
)
del log.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-75] ��� �޽��� ���� >> W1~82\report.txt

reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system" > W1~82\log\[W-75]log.txt

echo [W-75] �α��� ��� �޽��� ���� �� ������ �����Ǿ� ���� ���� ���, log ������ ���� �����ڿ� �Բ� ����Ȯ�� ��� - [���] > W1~82\bad\[W-75S]bad.txt 
echo [W-75] ����-����-SECPOL.MSC-������å-���ȿɼ�-�α׿� �õ��ϴ� ����ڿ� ���� �޽��� ����(legalnoticecaption) - ��� �����Է� >> W1~82\action\[W-75S]action.txt
echo [W-75] ����-����-SECPOL.MSC-������å-���ȿɼ�-�α׿� �õ��ϴ� ����ڿ� ���� �޽��� �ؽ�Ʈ(legalnoticetext) - ��� �����Է� >> W1~82\action\[W-75S]action.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� ���� �׸� �������� 6���� �ο��� �ֽʽÿ�. >> W1~82\action\[W-75S]action.txt


echo [W-75] �α��� ��� �޽��� ���� �� ������ �����Ǿ� ���� ���� ���, log ������ ���� �����ڿ� �Բ� ����Ȯ�� ��� - [���] >> W1~82\report.txt
echo [W-75] ����-����-SECPOL.MSC-������å-���ȿɼ�-�α׿� �õ��ϴ� ����ڿ� ���� �޽��� ����(legalnoticecaption) - ��� �����Է� >> W1~82\report.txt
echo [W-75] ����-����-SECPOL.MSC-������å-���ȿɼ�-�α׿� �õ��ϴ� ����ڿ� ���� �޽��� �ؽ�Ʈ(legalnoticetext) - ��� �����Է� >> W1~82\report.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� ���� �׸� �������� 6���� �ο��� �ֽʽÿ�. >>  W1~82\report.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-76] ����ں� Ȩ ���丮 ���� ���� >> W1~82\report.txt

icacls "c:\users\Administrator" > log.txt
icacls "c:\users\Administrator" > W1~82/log/[W-76]log.txt

type log.txt | find /i "everyone" > nul
if %errorlevel% EQU 0 (
 echo [W-76] Ȩ ���丮�� Everyone ������ �ִ� ��� - [���] > W1~82/bad/[W-76]bad.txt
 echo [W-76] ȨC:\�����\[����� ����] >> W1~82/action/[W-76]action.txt
 echo [W-76] "All Users, Default USer"�� ���� ���� �� �Ϲݰ��� ���� >> W1~82/action/[W-76]action.txt

 echo [W-76] Ȩ ���丮�� Everyone ������ �ִ� ��� - [���] >> W1~82\report.txt
 echo [W-76] ȨC:\�����\[����� ����] >> W1~82\report.txt
 echo [W-76] "All Users, Default USer"�� ���� ���� �� �Ϲݰ��� ���� >> W1~82\report.txt
) else (
 echo [W-76] Ȩ ���丮�� Everyone ������ ���� ��� - [��ȣ] > W1~82/good/[W-76]good.txt
 echo [W-76] Ȩ ���丮�� Everyone ������ ���� ��� - [��ȣ] >> W1~82\report.txt
 SET/a SecureScore = %SecureScore%+9
 SET/a SecureScore2 = %SecureScore2%+1
)

del log.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-77] LAN Manager ���� ���� >> W1~82\report.txt

secedit /EXPORT /CFG LocalSecurityPolicy.txt
type LocalSecurityPolicy.txt | find /i "LmCompatibilityLevel" > W1~82/log/[W-77]log.txt
type LocalSecurityPolicy.txt | find /i "LmCompatibilityLevel=4,3" > nul

if %errorlevel% EQU 0 (
 echo [W-77] "LAN Manager ���� ����" ��å�� "NTLMv2 ���丸 ����" �� �����Ǿ� �ִ� ��� - [��ȣ] > W1~82/good/[W-77]good.txt
 echo [W-77] "LAN Manager ���� ����" ��å�� "NTLMv2 ���丸 ����" �� �����Ǿ� �ִ� ��� - [��ȣ] >> W1~82\report.txt
 SET/a SecureScore = %SecureScore%+9
 SET/a SecureScore2 = %SecureScore2%+1

) else (
 echo [W-77] "LAN Manager ���� ����" ��å�� "NTLMv2 ���丸 ����" �� �����Ǿ� ���� ���� ��� - [���] > W1~82/bad/[W-77]bad.txt
 echo [W-77] ���� - ���� - SECPOL.MSC - ���� ��å - ���� �ɼ� >> W1~82/action/[W-77]action.txt
 echo [W-77] "��Ʈ��ũ ���� : LAN Manager ���� ����" ��å�� "NTLMv2 ���丸 ����" ���� >> W1~82/action/[W-77]action.txt

 echo [W-77] "LAN Manager ���� ����" ��å�� "NTLMv2 ���丸 ����" �� �����Ǿ� ���� ���� ��� - [���] >> W1~82\report.txt
 echo [W-77] ���� - ���� - SECPOL.MSC - ���� ��å - ���� �ɼ� >> W1~82\report.txt
 echo [W-77] "��Ʈ��ũ ���� : LAN Manager ���� ����" ��å�� "NTLMv2 ���丸 ����" ���� >> W1~82\report.txt
)

del LocalSecurityPolicy.txt

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-78] ���� ä�� ������ ������ ��ȣȭ �Ǵ� ���� >> W1~82\report.txt
SET/a W78S=0

reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" >> W1~82\log\[W-78]log.txt
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | find /I "requiresignorseal" >> logre.txt
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | find /I "sealsecurechannel" >> logse.txt     
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | find /I "signsecurechannel" >> logsi.txt     

type logre.txt | findstr /I "0x1"
if %errorlevel% EQU 0 (
	echo [W-78-1] ������ ������: ���� ä�� �����͸� ������ ��ȣȭ �Ǵ� ���� '���' - [��ȣ] >> W1~82\good\[W-78]good.txt
	echo [W-78-1] ������ ������: ���� ä�� �����͸� ������ ��ȣȭ �Ǵ� ���� '���' - [��ȣ] >> W1~82\report.txt
	SET/a SecureScore = %SecureScore%+3
	SET/a W78S=1

) else (
	echo [W-78-1] ������ ������: ���� ä�� �����͸� ������ ��ȣȭ �Ǵ� ���� '��� �� ��' - [���] >> W1~82\bad\[W-78]bad.txt
	echo [W-78-1] ����-����-SECPOL.MSC-���� ��å-���� �ɼ� >> W1~82\action\[W-78]action.txt
	echo [W-78-1] ������ ������: ���� ä�� �����͸� ������ ��ȣȭ �Ǵ� ���� ��å '���'���� ���� >> W1~82\action\[W-78]action.txt

	echo [W-78-1] ������ ������: ���� ä�� �����͸� ������ ��ȣȭ �Ǵ� ���� '��� �� ��' - [���] >> W1~82\report.txt
	echo [W-78-1] ����-����-SECPOL.MSC-���� ��å-���� �ɼ� >> W1~82\report.txt
	echo [W-78-1] ������ ������: ���� ä�� �����͸� ������ ��ȣȭ �Ǵ� ���� ��å '���'���� ���� >> W1~82\report.txt
)

type logsi.txt | findstr /I "0x1"
if %errorlevel% EQU 0 (
	echo [W-78-2] ������ ������: ���� ä�� ������ ������ ���� '���' - [��ȣ] >> W1~82\good\[W-78]good.txt
	echo [W-78-2] ������ ������: ���� ä�� ������ ������ ���� '���' - [��ȣ] >> W1~82\report.txt
	SET/a SecureScore = %SecureScore%+3
	SET/a W78S=1
) else (
	echo [W-78-2] ������ ������: ���� ä�� ������ ������ ���� '��� �� ��' - [���] >> W1~82\bad\[W-78]bad.txt
	echo [W-78-2] ����-����-SECPOL.MSC-���� ��å-���� �ɼ� >> W1~82\action\[W-78]action.txt
	echo [W-78-2] ������ ������: ���� ä�� ������ ������ ���� ��å '���'���� ���� >> W1~82\action\[W-78]action.txt

	echo [W-78-2] ������ ������: ���� ä�� ������ ������ ���� '��� �� ��' - [���] >> W1~82\report.txt
	echo [W-78-2] ����-����-SECPOL.MSC-���� ��å-���� �ɼ� >> W1~82\report.txt
	echo [W-78-2] ������ ������: ���� ä�� ������ ������ ���� ��å '���'���� ���� >> W1~82\report.txt
)

type logse.txt | findstr /I "0x1"
if %errorlevel% EQU 0 (
	echo [W-78-3] ������ ������: ���� ä�� ������ ������ ��ȣȭ '���' - [��ȣ] >> W1~82\good\[W-78]good.txt
	echo [W-78-3] ������ ������: ���� ä�� ������ ������ ��ȣȭ '���' - [��ȣ] >> W1~82\report.txt
	SET/a SecureScore = %SecureScore%+3
	SET/a W78S=1
) else (
	echo [W-78-3] ������ ������: ���� ä�� ������ ������ ��ȣȭ '��� �� ��' - [���] >> W1~82\bad\[W-78]bad.txt
	echo [W-78-3] ����-����-SECPOL.MSC-���� ��å-���� �ɼ� >> W1~82\action\[W-78]action.txt
	echo [W-78-3] ������ ������: ���� ä�� �����͸� ������ ��ȣȭ ��å '���'���� ���� >> W1~82\action\[W-78]action.txt

	echo [W-78-3] ������ ������: ���� ä�� ������ ������ ��ȣȭ '��� �� ��' - [���] >> W1~82\report.txt
	echo [W-78-3] ����-����-SECPOL.MSC-���� ��å-���� �ɼ� >> W1~82\report.txt
	echo [W-78-3] ������ ������: ���� ä�� �����͸� ������ ��ȣȭ ��å '���'���� ���� >> W1~82\report.txt
)

del logre.txt
del logse.txt
del logsi.txt

if %W78S% EQU 1 (
	SET/a SecureScore2 = %SecureScore2%+1
)

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-79] ���� �� ���丮 ��ȣ >> W1~82\report.txt
SET/a W79S=1

chkntfs c: >> W1~82\log\[W-79]log.txt                
chkntfs d: >> W1~82\log\[W-79]log.txt                   
chkntfs e: >> W1~82\log\[W-79]log.txt                 
chkntfs f: >> W1~82\log\[W-79]log.txt
chkntfs c: >> logc.txt                
chkntfs d: >> logd.txt                   
chkntfs e: >> loge.txt                 
chkntfs f: >> logf.txt 

type logc.txt | find /I "C: ����̺갡 �����ϴ�."
if %errorlevel% EQU 0 (
	echo [W-79] C����̺갡 ���� - [��ȣ] >> W1~82\good\[W-79]good.txt 
	echo [W-79] C����̺갡 ���� - [��ȣ] >> W1~82\report.txt
) else (
goto W79C
)

:W79C
type logc.txt | find /I "NTFS"
if %errorlevel% EQU 0 (
	echo [W-79] C����̺갡 NTFS ���� �ý����� ����ϴ� ��� - [��ȣ] >> W1~82\good\[W-79]good.txt 
	echo [W-79] C����̺갡 NTFS ���� �ý����� ����ϴ� ��� - [��ȣ] >> W1~82\report.txt
) else (
	echo [W-79] C����̺갡 FAT ���� �ý����� ����ϴ� ��� - [���] >> W1~82\bad\[W-79]bad.txt
	echo [W-79] ��ɾ� ������Ʈ[DOSâ]���� ������ ���� �Է� >> W1~82\action\[W-79]action.txt
	echo [W-79] ���� - ���� - CMD - convert C: /fs:ntfs >> W1~82\action\[W-79]action.txt

	echo [W-79] C����̺갡 FAT ���� �ý����� ����ϴ� ��� - [���] >> W1~82\report.txt
	echo [W-79] ��ɾ� ������Ʈ[DOSâ]���� ������ ���� �Է� >> W1~82\report.txt
	echo [W-79] ���� - ���� - CMD - convert C: /fs:ntfs >> W1~82\report.txt
	SET/a W79S=0
) 

type logd.txt | find /I "D: ����̺갡 �����ϴ�."
if %errorlevel% EQU 0 (
	echo [W-79] D����̺갡 ���� - [��ȣ] >> W1~82\good\[W-79]good.txt 
	echo [W-79] D����̺갡 ���� - [��ȣ] >> W1~82\report.txt
	goto W79E
) else (
goto W79D
)

:W79D
type logd.txt | find /I "NTFS"
if %errorlevel% EQU 0 (
	echo [W-79] D����̺갡 NTFS ���� �ý����� ����ϴ� ��� - [��ȣ] >> W1~82\good\[W-79]good.txt 
	echo [W-79] D����̺갡 NTFS ���� �ý����� ����ϴ� ��� - [��ȣ] >> W1~82\report.txt
) else (
	echo [W-79] D����̺갡 FAT ���� �ý����� ����ϴ� ��� - [���] >> W1~82\bad\[W-79]bad.txt
	echo [W-79] ��ɾ� ������Ʈ[DOSâ]���� ������ ���� �Է� >> W1~82\action\[W-79]action.txt
	echo [W-79] ���� - ���� - CMD - convert D: /fs:ntfs >> W1~82\action\[W-79]action.txt

	echo [W-79] D����̺갡 FAT ���� �ý����� ����ϴ� ��� - [���] >> W1~82\report.txt
	echo [W-79] ��ɾ� ������Ʈ[DOSâ]���� ������ ���� �Է� >> W1~82\report.txt
	echo [W-79] ���� - ���� - CMD - convert D: /fs:ntfs >> W1~82\report.txt
	SET/a W79S=0
) 

:W79E
type loge.txt | find /I "E: ����̺갡 �����ϴ�."
if %errorlevel% EQU 0 (
	echo [W-79] E����̺갡 ���� - [��ȣ] >> W1~82\good\[W-79]good.txt 
	echo [W-79] E����̺갡 ���� - [��ȣ] >> W1~82\report.txt
	goto W79F
) else (
goto W79E2
)

:W79E2
type loge.txt | find /I "NTFS"
if %errorlevel% EQU 0 (
	echo [W-79] E����̺갡 NTFS ���� �ý����� ����ϴ� ��� - [��ȣ] >> W1~82\good\[W-79]good.txt 
	echo [W-79] E����̺갡 NTFS ���� �ý����� ����ϴ� ��� - [��ȣ] >> W1~82\report.txt 
) else (
	echo [W-79] E����̺갡 FAT ���� �ý����� ����ϴ� ��� - [���] >> W1~82\bad\[W-79]bad.txt
	echo [W-79] ��ɾ� ������Ʈ[DOSâ]���� ������ ���� �Է� >> W1~82\action\[W-79]action.txt
	echo [W-79] ���� - ���� - CMD - convert E: /fs:ntfs >> W1~82\action\[W-79]action.txt

	echo [W-79] E����̺갡 FAT ���� �ý����� ����ϴ� ��� - [���] >> W1~82\report.txt
	echo [W-79] ��ɾ� ������Ʈ[DOSâ]���� ������ ���� �Է� >> W1~82\report.txt
	echo [W-79] ���� - ���� - CMD - convert E: /fs:ntfs >> W1~82\report.txt
	SET/a W79S=0
) 

:W79F
type logf.txt | find /I "F: ����̺갡 �����ϴ�."
if %errorlevel% EQU 0 (
	echo [W-79] F����̺갡 ���� - [��ȣ] >> W1~82\good\[W-79]good.txt 
	echo [W-79] F����̺갡 ���� - [��ȣ] >> W1~82\report.txt
	goto W79RM
) else (
goto W79F2
)

:W79GF2
type logf.txt | find /I "NTFS"
if %errorlevel% EQU 0 (
	echo [W-79] F����̺갡 NTFS ���� �ý����� ����ϴ� ��� - [��ȣ] >> W1~82\good\[W-79]good.txt
	echo [W-79] F����̺갡 NTFS ���� �ý����� ����ϴ� ��� - [��ȣ] >> W1~82\report.txt
) else (
	echo [W-79] F����̺갡 FAT ���� �ý����� ����ϴ� ��� - [���] >> W1~82\bad\[W-79]bad.txt
	echo [W-79] ��ɾ� ������Ʈ[DOSâ]���� ������ ���� �Է� >> W1~82\action\[W-79]action.txt
	echo [W-79] ���� - ���� - CMD - convert F: /fs:ntfs >> W1~82\action\[W-79]action.txt

	echo [W-79] F����̺갡 FAT ���� �ý����� ����ϴ� ��� - [���] >> W1~82\report.txt
	echo [W-79] ��ɾ� ������Ʈ[DOSâ]���� ������ ���� �Է� >> W1~82\report.txt
	echo [W-79] ���� - ���� - CMD - convert F: /fs:ntfs >> W1~82\report.txt
	SET/a W79S=0
) 

:W79RM
del logc.txt
del logd.txt
del loge.txt
del logf.txt

if %W79S% EQU 1 (
	SET/a SecureScore = %SecureScore%+9
	SET/a SecureScore2 = %SecureScore2%+1
)

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-80] ��ǻ�� ���� ��ȣ �ִ� ��� �Ⱓ >> W1~82\report.txt
SET/a W80S=0
SET/a W80S1=0
SET/a W80S2=0

reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | find /I "DisablePasswordChange" >> W1~82\log\[W-80]log.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | find /I "maximumpasswordage" >> W1~82\log\[W-80]log.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | find /I "DisablePasswordChange" > logd.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | find /I "maximumpasswordage" > logm.txt

type logd.txt | find /I "0x0" 
if %errorlevel% EQU 0 (
	echo [W-80] '��ǻ�� ���� ��ȣ ���� ��� �� ��' ��å�� ������� ���� - [��ȣ] >> W1~82/good/[W-80]good.txt
	echo [W-80] '��ǻ�� ���� ��ȣ ���� ��� �� ��' ��å�� ������� ���� - [��ȣ] >> W1~82\report.txt
	SET/a SecureScore = %SecureScore%+4
	SET/a W80S=1
) else (
	echo [W-80] '��ǻ�� ���� ��ȣ ���� ��� �� ��' ��å�� ����� - [���] >> W1~82/bad/[W-80]bad.txt
	echo [W-80] ����-����-SECPOL.MSC-���� ��å-���� �ɼ� >> W1~82/action/[W-80]action.txt
	echo [W-80] ������ ������: ��ǻ�� ���� ��ȣ ���� ���� ��� �� �� �� ��� �� �� >> W1~82/action/[W-80]action.txt

	echo [W-80] '��ǻ�� ���� ��ȣ ���� ��� �� ��' ��å�� ����� - [���] >> W1~82\report.txt
	echo [W-80] ����-����-SECPOL.MSC-���� ��å-���� �ɼ� >> W1~82\report.txt
	echo [W-80] ������ ������: ��ǻ�� ���� ��ȣ ���� ���� ��� �� �� �� ��� �� �� >> W1~82\report.txt
)

type logm.txt | find /I "0x5a" 
if %errorlevel% EQU 0 (
	echo [W-80] '��ǻ�� ���� ��ȣ �ִ� ��� �Ⱓ' ��å�� '90��'�� �����Ǿ� �ִ� ��� - [��ȣ] >> W1~82/good/[W-80]good.txt
	echo [W-80] '��ǻ�� ���� ��ȣ �ִ� ��� �Ⱓ' ��å�� '90��'�� �����Ǿ� �ִ� ��� - [��ȣ] >> W1~82\report.txt
	SET/a SecureScore = %SecureScore%+4
	SET/a W80S=1
) else (
	echo [W-80] '��ǻ�� ���� ��ȣ �ִ� ��� �Ⱓ' ��å�� '90��'�� �����Ǿ� ���� �ʴ� ��� - [���] >> W1~82/bad/[W-80]bad.txt
	echo [W-80] ����-����-SECPOL.MSC-���� ��å-���� �ɼ� >> W1~82/action/[W-80]action.txt
	echo [W-80] ������ ������: ��ǻ�� ���� ��ȣ�� �ִ� ��� �Ⱓ �� 90�� >> W1~82/action/[W-80]action.txt

	echo [W-80] '��ǻ�� ���� ��ȣ �ִ� ��� �Ⱓ' ��å�� '90��'�� �����Ǿ� ���� �ʴ� ��� - [���] >> W1~82\report.txt
	echo [W-80] ����-����-SECPOL.MSC-���� ��å-���� �ɼ� >> W1~82\report.txt
	echo [W-80] ������ ������: ��ǻ�� ���� ��ȣ�� �ִ� ��� �Ⱓ �� 90�� >> W1~82\report.txt
)

del logd.txt
del logm.txt

if %W80S% EQU 1 (
	SET/a SecureScore3 = %SecureScore3%+1
)
if %W80S1% EQU 1 (
	if %W80S2% EQU 1 (
		SET/a SecureScore = %SecureScore%+1
	)
)

echo. >> W1~82\report.txt

echo. >> W1~82\report.txt

echo [W-81] �������α׷� ��� �м� >> W1~82\report.txt

echo "�������α׷� ���" >> W1~82\log\[W-81]log.txt
dir "C:\Users\Administarator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" >> W1~82\log\[W-81]log.txt
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" >> W1~82\log\[W-81]log.txt
echo. >> W1~82\log\[W-81]log.txt

echo "������Ʈ�� Run ���" >> W1~82\log\[W-81]log.txt
echo "Windows x86 �������α׷� ���" >> W1~82\log\[W-81]log.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" >> W1~82\log\[W-81]log.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >> W1~82\log\[W-81]log.txt
echo. >> W1~82\log\[W-81]log.txt

echo "Windows x64 �������α׷� ���" >> W1~82\log\[W-81]log.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" >> W1~82\log\[W-81]log.txt

echo [W-81] �������α׷� ����� ���������� �˻��ϰ� ���ʿ��� ���� üũ ������ �� ��� (2012 ���� �ش� ����) >> W1~82\good\[W-81SS]good.txt
echo [W-81] �������α׷� ����� ���������� �˻����� �ʰ�, ���� �� ���ʿ��� ���񽺵� ����ǰ� �ִ� ��� >> W1~82\bad\[W-81SS]bad.txt
echo [W-81] ���� - �˻� - msconfig ��ɾ� �Է� >> W1~82\action\[W-81SS]action.txt
echo [W-81] ���� ���α׷� �� Ŭ�� - ���� ���α׷� ��� �� ���ʿ��ϰų� �ǽɽ����� �׸� üũ ǥ�� ���� >> W1~82\action\[W-81SS]action.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� ���� �׸� �������� 9���� �ο��� �ֽʽÿ�. >> W1~82\action\[W-81SS]action.txt


echo [W-81] �������α׷� ����� ���������� �˻��ϰ� ���ʿ��� ���� üũ ������ �� ��� (2012 ���� �ش� ����) >> W1~82\report.txt
echo [W-81] �������α׷� ����� ���������� �˻����� �ʰ�, ���� �� ���ʿ��� ���񽺵� ����ǰ� �ִ� ��� >> W1~82\report.txt
echo [W-81] ���� - �˻� - msconfig ��ɾ� �Է� >> W1~82\report.txt
echo [W-81] ���� ���α׷� �� Ŭ�� - ���� ���α׷� ��� �� ���ʿ��ϰų� �ǽɽ����� �׸� üũ ǥ�� ���� >> W1~82\report.txt
echo ����, �� ���˺κп��� ��ȣ�ϴٰ� �Ǵ��� �ȴٸ�, ���� ���� �׸� �������� 9���� �ο��� �ֽʽÿ�. >>  W1~82\report.txt


echo. >> W1~82\report.txt

echo. >> W1~82\report.txt


echo %AccountScore%
echo %AccountScore2%
echo %AccountScore3%
echo %AccountScore% > W1~82\Score\AScore.txt
echo %AccountScore2% > W1~82\Score\AScore2.txt
echo %AccountScore3% > W1~82\Score\AScore3.txt
echo %ServiceScore%
echo %ServiceScore1%
echo %ServiceScore2%
echo %ServiceScore3%
echo %ServiceScore% > W1~82\Score\SScore.txt
echo %ServiceScore1% > W1~82\Score\SSCore1.txt
echo %ServiceScore2% > W1~82\Score\SScore2.txt
echo %ServiceScore3% > W1~82\Score\SScore3.txt
echo %PatchScore%
echo %PatchScore2%
echo %PatchScore3%
echo %PatchScore% > W1~82\Score\PScore.txt
echo %PatchScore2% > W1~82\Score\PScore2.txt
echo %PatchScore3% > W1~82\Score\PScore3.txt
echo %LogScore%
echo %LogScore1%
echo %LogScore2%
echo %LogScore3%
echo %LogScore% > W1~82\Score\LScore.txt
echo %LogScore1% > W1~82\Score\LScore1.txt
echo %LogScore2% > W1~82\Score\LScore2.txt
echo %LogScore3% > W1~82\Score\LScore3.txt
echo %SecureScore%
echo %SecureScore2%
echo %SecureScore3%
echo %SecureScore% > W1~82\Score\SeScore.txt
echo %SecureScore2% > W1~82\Score\SeScore2.txt
echo %SecureScore3% > W1~82\Score\SeScore3.txt
pause




