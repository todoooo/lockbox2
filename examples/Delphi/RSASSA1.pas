unit RSASSA1;

interface

uses
{$IFDEF WIN32}
  Windows,
  Messages,
  Graphics,
  Controls,
  Forms,
  Dialogs,
  StdCtrls,
  ExtCtrls,
  ComCtrls,
{$ENDIF}
{$IFDEF LINUX}
  QForms,
  QStdCtrls,
  QControls,
  QExtCtrls,
  QComCtrls,
{$ENDIF}
  SysUtils,
  Classes,
  LbCipher,
  LbClass,
  LbAsym,
  LbRSA;

type
  TForm1 = class(TForm)
    LbRSASSA1: TLbRSASSA;
    StatusBar1: TStatusBar;
    GroupBox1: TGroupBox;
    Label2: TLabel;
    cbxKeySize: TComboBox;
    btnGenKeys: TButton;
    Label4: TLabel;
    btnSign: TButton;
    btnVerify: TButton;
    Label3: TLabel;
    cbxHashMethod: TComboBox;
    chkAbort: TCheckBox;
    btnLoadPublic: TButton;
    OpenDialog1: TOpenDialog;
    btnLoadPrivate: TButton;
    GroupBox2: TGroupBox;
    mmoSignature: TMemo;
    rbnHexidecimal: TRadioButton;
    rbnBase64: TRadioButton;
    edtMsg: TMemo;
    procedure btnSignClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure btnGenKeysClick(Sender: TObject);
    procedure btnVerifyClick(Sender: TObject);
    procedure cbxKeySizeChange(Sender: TObject);
    procedure cbxHashMethodChange(Sender: TObject);
    procedure LbRSASSA1GetSignature(Sender: TObject;
      var Sig: TRSASignatureBlock);
    procedure LbRSASSA1Progress(Sender: TObject; var Abort: Boolean);
    procedure btnLoadPublicClick(Sender: TObject);
    procedure btnLoadPrivateClick(Sender: TObject);
    procedure rbnHexidecimalClick(Sender: TObject);
    procedure rbnBase64Click(Sender: TObject);
  private

  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

uses
  LbUtils, LbBigInt;

const
  sPass = ' Signature verification: PASSED';
  sFail = ' Signature verification: FAILED';
  sSigning = ' Generating signature';
  sPatience = ' Generating RSA key pair- this may take a while';
  sAbort = ' Key generation aborted';

procedure TForm1.FormCreate(Sender: TObject);
  { initialize edit controls }
begin
  cbxHashMethod.ItemIndex := Ord(LbRSASSA1.HashMethod);
  cbxKeySize.ItemIndex := Ord(LbRSASSA1.KeySize) - 1;
end;

procedure TForm1.btnGenKeysClick(Sender: TObject);
  { generate RSA key pair }
begin
  Screen.Cursor := crAppStart;
  StatusBar1.SimpleText := sPatience;
  try
    LbRSASSA1.GenerateKeyPair;
  finally
    Screen.Cursor := crDefault;
    if chkAbort.Checked then
      StatusBar1.SimpleText := sAbort
    else
      StatusBar1.SimpleText := '';
  end;
end;

procedure TForm1.btnLoadPrivateClick(Sender: TObject);
var
  FS : TFileStream;
begin
  if OpenDialog1.Execute then begin
    FS := TFileStream.Create(OpenDialog1.FileName, fmOpenRead);
    Screen.Cursor := crHourGlass;
    try
      LbRSASSA1.PrivateKey.LoadFromStream(FS);
    finally
      FS.Free;
      Screen.Cursor := crDefault;
    end;
  end;
end;

procedure TForm1.btnLoadPublicClick(Sender: TObject);
var
  FS : TFileStream;
begin
  if OpenDialog1.Execute then begin
    FS := TFileStream.Create(OpenDialog1.FileName, fmOpenRead);
    Screen.Cursor := crHourGlass;
    try
      LbRSASSA1.PublicKey.LoadFromStream(FS);
    finally
      FS.Free;
      Screen.Cursor := crDefault;
    end;
  end;
end;

procedure TForm1.btnSignClick(Sender: TObject);
  { sign message string, display signature as hex string }
var
  SignatureCopy : TLbBigInt;
begin
  Screen.Cursor := crHourglass;
  StatusBar1.SimpleText := sSigning;
  try
    LbRSASSA1.SignString(StringToUTF8(edtMsg.Text));

    SignatureCopy := TLbBigInt.Create(LbRSASSA1.Signature.Size);
    try
      SignatureCopy.Copy(LbRSASSA1.Signature);
      SignatureCopy.PowerAndMod(LbRSASSA1.PublicKey.Exponent,LbRSASSA1.PublicKey.Modulus);
      SignatureCopy.ReverseBytes;
    finally
      SignatureCopy.Free;
    end;

    if rbnBase64.Checked then
    begin
      mmoSignature.Text := LbRSASSA1.Signature.Base64Str;
    end
    else
    begin
      mmoSignature.Text := LbRSASSA1.Signature.IntStr;
    end;

    mmoSignature.Font.Color := clRed;
  finally
    Screen.Cursor := crDefault;
    StatusBar1.SimpleText := '';
  end;
end;

procedure TForm1.btnVerifyClick(Sender: TObject);
  { verify signature against message }
begin
  StatusBar1.SimpleText := sFail;
  if LbRSASSA1.VerifyString(StringToUTF8(edtMsg.Text)) then
  begin
    StatusBar1.SimpleText := sPass;
    mmoSignature.Font.Color := clGreen;
  end;
end;

procedure TForm1.LbRSASSA1GetSignature(Sender: TObject; var Sig: TRSASignatureBlock);
  { convert signature string to binary and return it }
var
  BufferSize : Cardinal;
begin
  if rbnBase64.Checked then
  begin
    Base64ToBuffer(mmoSignature.Text, Sig, BufferSize);
  end
  else
  begin
    HexToBuffer(mmoSignature.Text, Sig, SizeOf(Sig));
  end;
end;

procedure TForm1.cbxKeySizeChange(Sender: TObject);
  { key size changed }
begin
  LbRSASSA1.KeySize := TLbAsymKeySize(cbxKeySize.ItemIndex + 1);
end;

procedure TForm1.cbxHashMethodChange(Sender: TObject);
  { hash method changed }
begin
  LbRSASSA1.HashMethod := TRSAHashMethod(cbxHashMethod.ItemIndex);
end;

procedure TForm1.LbRSASSA1Progress(Sender: TObject; var Abort: Boolean);
  { process message loop and abort if need be }
begin
  Application.ProcessMessages;
  Abort := chkAbort.Checked;
end;

procedure TForm1.rbnBase64Click(Sender: TObject);
begin
  rbnHexidecimal.Checked := False;
  mmoSignature.Text := LbRSASSA1.Signature.Base64Str;
end;

procedure TForm1.rbnHexidecimalClick(Sender: TObject);
begin
  rbnBase64.Checked := False;
  mmoSignature.Text := LbRSASSA1.Signature.IntStr;
end;

end.
