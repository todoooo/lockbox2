�
 TLBRSAKEYSFORM 0_  TPF0TlbRSAKeysFormlbRSAKeysFormLeftTop� Caption=RSAKeys - Public/private key manager (using TLbRSA component)ClientHeight�ClientWidth�Color	clBtnFaceConstraints.MinHeight�Constraints.MinWidth�Font.CharsetDEFAULT_CHARSET
Font.ColorclWindowTextFont.Height�	Font.NameMS Sans Serif
Font.Style OldCreateOrder	PixelsPerInch`
TextHeight 
TStatusBar	sbrVerifyLeft Top�Width�HeightPanels SimplePanel	  TPanelpnlPersistKeysLeft Top Width�Height�AlignalClient
BevelOuterbvNoneBorderWidth
TabOrder 	TGroupBoxgrpPersistKeysLeft
Top
WidthnHeight�AlignalClientCaption	 Key PairTabOrder  TPanelpnlKeysLeftTopAWidthjHeightGAlignalClient
BevelOuterbvNoneBorderWidth
TabOrder  TTabControltbcKeyVisibilityLeft
Top
WidthVHeight3AlignalClientTabOrder Tabs.StringsPublicPrivate TabIndex OnChangetbcKeyVisibilityChange
DesignSizeV3  TLabellblExponentLeftTop.Width-HeightCaptionExponent  TLabellblPassPhraseLeftTopWidth;HeightAnchorsakLeftakBottom CaptionPass PhraseExplicitTop�   TLabel
lblModulusLeftTopZWidth(HeightCaptionModulus  TLabellblEncodingLeftKTop� Width-HeightCaptionEncoding  TEditedtExponentLeftKTop+Width�HeightAnchorsakLeftakTopakRight TabOrder   TButtonbtnLoadLeftKTopWidthUHeightAnchorsakLeftakBottom Caption
Load ASN.1TabOrderOnClickbtnLoadClick  TButtonbtnSaveLeft� TopWidthUHeightAnchorsakLeftakBottom Caption
Save ASN.1TabOrderOnClickbtnSaveClick  TEditedtPassPhraseLeftTTopWidth� HeightAnchorsakLeftakRightakBottom TabOrder  TMemo
mmoModulusLeftKTopFWidth�Height<AnchorsakLeftakTopakRight ReadOnly	TabOrder  	TCheckBox
chkOpenSSLLeftTop� WidthAHeightAnchorsakTopakRight CaptionOpenSSLTabOrderOnClickchkOpenSSLClick  TMemommoFormattedTextLeftKTop� Width�HeightRAnchorsakLeftakTopakRightakBottom TabOrder  	TComboBoxcmbEncodingLeft~Top� Width� Height	ItemIndex TabOrderTextBase64 - ASN.1OnChangecmbEncodingChangeItems.StringsBase64 - ASN.1XML - CryptoServiceProvider     TPanel
pnlKeySizeLeftTopWidthjHeight2AlignalTop
BevelOuterbvNoneBorderWidth
TabOrder TLabel
lblKeySizeLeft9TopWidth)HeightCaptionKey Size  TLabellblIterationsLeft� TopWidth[Height	AlignmenttaRightJustifyCaptionPrime test iterationsWordWrap	  	TComboBox
cmbKeySizeLefthTop
WidthdHeightStylecsDropDownListConstraints.MinWidthdTabOrder OnChangecmbKeySizeChangeItems.Strings1282565127681024   TEditedtIterationsLeftHTop
Width!HeightTabOrderText20  TButtonbtnCreateKeysLeft�TopWidth`HeightCaptionGenerate KeysTabOrderOnClickbtnCreateKeysClick  	TCheckBoxchkFixedExponentLeft Top
WidthaHeightCaptionFixed ExponentTabOrder     TSaveDialogdlgSaveLeftTop�   TOpenDialogdlgOpenLeft�Top�   TLbRSAkpRSAPrimeTestIterationsKeySizeaks128Left0Top(   