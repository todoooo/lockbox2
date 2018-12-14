unit RSAKeys1;

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
  QDialogs,
  QControls,
  QExtCtrls,
  QComCtrls,
  QStdCtrls,
{$ENDIF}
  SysUtils,
  Classes,
  LbAsym,
  LbRSA,
  LbCipher,
  LbClass;

type
  TlbRSAKeysForm = class(TForm)
    sbrVerify: TStatusBar;
    pnlPersistKeys: TPanel;
    grpPersistKeys: TGroupBox;
    dlgSave: TSaveDialog;
    dlgOpen: TOpenDialog;
    pnlKeys: TPanel;
    tbcKeyVisibility: TTabControl;
    lblExponent: TLabel;
    edtExponent: TEdit;
    btnLoad: TButton;
    btnSave: TButton;
    edtPassPhrase: TEdit;
    lblPassPhrase: TLabel;
    lblModulus: TLabel;
    mmoModulus: TMemo;
    pnlKeySize: TPanel;
    lblKeySize: TLabel;
    cmbKeySize: TComboBox;
    lblIterations: TLabel;
    edtIterations: TEdit;
    btnCreateKeys: TButton;
    chkFixedExponent: TCheckBox;
    kpRSA: TLbRSA;
    chkOpenSSL: TCheckBox;
    mmoFormattedText: TMemo;
    cmbEncoding: TComboBox;
    lblEncoding: TLabel;
    procedure btnCreateKeysClick(Sender: TObject);
    procedure btnLoadClick(Sender: TObject);
    procedure btnSaveClick(Sender: TObject);
    procedure tbcKeyVisibilityChange(Sender: TObject);
    procedure cmbKeySizeChange(Sender: TObject);
    procedure chkOpenSSLClick(Sender: TObject);
    procedure cmbEncodingChange(Sender: TObject);
  private
    FActiveKey : TLbRSAKey;
    procedure UpdateControls;
    procedure SetKeySize(const AValue : TLbAsymKeySize);
  public
    procedure AfterConstruction; override;
  end;

var
  lbRSAKeysForm: TlbRSAKeysForm;

implementation

{$R *.dfm}

uses
  LbUtils, LbBigInt;

procedure TlbRSAKeysForm.AfterConstruction;
begin
  inherited;
//  cmbKeySize.ItemIndex := Ord(kpRSA.KeySize);
  FActiveKey := kpRSA.PublicKey;
  UpdateControls;
end;

procedure TlbRSAKeysForm.btnCreateKeysClick(Sender: TObject);
var
  Exponent : TLbBigInt;
begin
  Screen.Cursor := crHourglass;
  sbrVerify.SimpleText := 'Generating key pair, this may take a while';
  try
    kpRSA.PrimeTestIterations := StrToIntDef(edtIterations.Text, 20);
    kpRSA.KeySize := TLbAsymKeySize(cmbKeySize.ItemIndex);
    if (chkFixedExponent.Checked) then
    begin
      Exponent := TLbBigInt.Create(0);
      try
        Exponent.IntStr := '010001';
        kpRSA.GenerateKeyPairWithExponent(Exponent);
      finally
        Exponent.Free;
      end;
    end
    else
    begin
      kpRSA.GenerateKeyPair;
    end;

    tbcKeyVisibilityChange(self);
  finally
    Screen.Cursor := crDefault;
    sbrVerify.SimpleText := '';
  end;
end;

procedure TlbRSAKeysForm.btnLoadClick(Sender: TObject);
var
  FS : TFileStream;
begin
  if dlgOpen.Execute then
  begin
    FS := TFileStream.Create(dlgOpen.FileName, fmOpenRead);
    Screen.Cursor := crHourGlass;
    try
      FActiveKey.Clear;
      FActiveKey.LoadFromStream(FS, StringToUTF8(edtPassPhrase.Text));
      SetKeySize(FActiveKey.KeySize);
      UpdateControls;
    finally
      FS.Free;
      Screen.Cursor := crDefault;
    end;
  end;
end;

procedure TlbRSAKeysForm.btnSaveClick(Sender: TObject);
var
  FS : TFileStream;
begin
  if dlgSave.Execute then
  begin
    FS := TFileStream.Create(dlgSave.FileName, fmCreate);
    Screen.Cursor := crHourGlass;
    try
      FActiveKey.StoreToStream(FS, StringToUTF8(edtPassPhrase.Text));
    finally
      FS.Free;
      Screen.Cursor := crDefault;
    end;
  end;
end;

procedure TlbRSAKeysForm.chkOpenSSLClick(Sender: TObject);
begin
  UpdateControls;
end;

procedure TlbRSAKeysForm.cmbEncodingChange(Sender: TObject);
begin
  chkOpenSSL.Enabled := (cmbEncoding.ItemIndex = 0);
  UpdateControls;
end;

procedure TlbRSAKeysForm.cmbKeySizeChange(Sender: TObject);
begin
  SetKeySize(TLbAsymKeySize(cmbKeySize.ItemIndex));
end;

procedure TlbRSAKeysForm.SetKeySize(const AValue: TLbAsymKeySize);
begin
  if (kpRSA.KeySize <> AValue) then
  begin
    if (kpRSA.PublicKey.KeySize <> AValue) then
    begin
      kpRSA.PublicKey.Clear;
    end;

    if (kpRSA.PrivateKey.KeySize <> AValue) then
    begin
      kpRSA.PrivateKey.Clear;
    end;

    kpRSA.KeySize := AValue;
    UpdateControls;
  end;
end;

procedure TlbRSAKeysForm.UpdateControls;
const
  BLOCK_FORMAT = '-----%s RSA %s KEY-----';
var
  MemoText, HeaderTag, FooterTag, PrivacyText : String;
begin
  edtExponent.Text := FActiveKey.ExponentAsString;
  mmoModulus.Text := FActiveKey.ModulusAsString;

  MemoText := '';
  if (FActiveKey.Exponent.Size > 0) and (FActiveKey.Modulus.Size > 0) then
  begin
    case cmbEncoding.ItemIndex of
      0:
      begin
        MemoText := UTF8ToString(FActiveKey.Base64EncodedText);
      end;

      1:
      begin
        MemoText := kpRSA.CryptoServiceProviderXML[FActiveKey = kpRSA.PrivateKey];
      end;
    end;

    if chkOpenSSL.Enabled and chkOpenSSL.Checked then
    begin
      PrivacyText := 'PUBLIC';
      if (FActiveKey = kpRSA.PrivateKey) then
      begin
        PrivacyText := 'PRIVATE';
      end;

      HeaderTag := Format(BLOCK_FORMAT,['BEGIN',PrivacyText]);
      FooterTag := Format(BLOCK_FORMAT,['END',PrivacyText]);

      MemoText := HeaderTag + sLineBreak + MemoText + sLineBreak + FooterTag;
    end;
  end;

  mmoFormattedText.Text := MemoText;
  cmbKeySize.ItemIndex := ord(FActiveKey.KeySize);
end;

procedure TlbRSAKeysForm.tbcKeyVisibilityChange(Sender: TObject);
begin
  if (tbcKeyVisibility.TabIndex = 0) then
  begin
    FActiveKey := kpRSA.PublicKey;
  end
  else
  begin
    FActiveKey := kpRSA.PrivateKey;
  end;

  UpdateControls;
end;

end.


