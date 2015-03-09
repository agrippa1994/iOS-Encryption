//
//  EncodingDecodingTableViewController.swift
//  Encryption
//
//  Created by Mani on 14.12.14.
//  Copyright (c) 2014 Mani. All rights reserved.
//

import UIKit

class EncodingDecodingTableViewController: UITableViewController, UIPickerViewDataSource, UIPickerViewDelegate, UITextFieldDelegate, UITextViewDelegate {

    struct Coding
    {
        var displayName: String
        var codingNameForCryptor: String
        var keyBits: Int
        var ivBits: Int
    }
    
    let codings = [Coding](arrayLiteral:
        Coding(displayName: "AES ECB 128-bit", codingNameForCryptor: "aes_ecb", keyBits: 128, ivBits: 0),
        Coding(displayName: "AES ECB 192-bit", codingNameForCryptor: "aes_ecb", keyBits: 192, ivBits: 0),
        Coding(displayName: "AES ECB 256-bit", codingNameForCryptor: "aes_ecb", keyBits: 256, ivBits: 0),
    
        Coding(displayName: "AES CBC 128-bit", codingNameForCryptor: "aes_cbc", keyBits: 128, ivBits: 128),
        Coding(displayName: "AES CBC 192-bit", codingNameForCryptor: "aes_cbc", keyBits: 192, ivBits: 128),
        Coding(displayName: "AES CBC 256-bit", codingNameForCryptor: "aes_cbc", keyBits: 256, ivBits: 128),
    
        Coding(displayName: "AES CFB 128-bit", codingNameForCryptor: "aes_cfb", keyBits: 128, ivBits: 128),
        Coding(displayName: "AES CFB 192-bit", codingNameForCryptor: "aes_cfb", keyBits: 192, ivBits: 128),
        Coding(displayName: "AES CFB 256-bit", codingNameForCryptor: "aes_cfb", keyBits: 256, ivBits: 128),
    
        Coding(displayName: "AES OFB 128-bit", codingNameForCryptor: "aes_ofb", keyBits: 128, ivBits: 128),
        Coding(displayName: "AES OFB 192-bit", codingNameForCryptor: "aes_ofb", keyBits: 192, ivBits: 128),
        Coding(displayName: "AES OFB 256-bit", codingNameForCryptor: "aes_ofb", keyBits: 256, ivBits: 128)
    )
    
    @IBOutlet var methodPickerView: UIPickerView!
    @IBOutlet var ivTableViewCell: UITableViewCell!
    @IBOutlet var ivSegmentedControl: UISegmentedControl!
    @IBOutlet var ivTextField: UITextField!
    @IBOutlet var keyTableViewCell: UITableViewCell!
    @IBOutlet var keySegmentedControl: UISegmentedControl!
    @IBOutlet var keyTextField: UITextField!
    @IBOutlet var inputTableViewCell: UITableViewCell!
    @IBOutlet var inputSegmentedControl: UISegmentedControl!
    @IBOutlet var inputTextView: UITextView!
    
    var currentTextView: UIView?
    var currentCryptData: NSData?
    var normalContentInset = UIEdgeInsetsZero
    
    override func viewDidLoad() {
        super.viewDidLoad()

        methodPickerView.dataSource = self
        methodPickerView.delegate = self
        ivTextField.delegate = self
        keyTextField.delegate = self
        inputTextView.delegate = self
        
        NSNotificationCenter.defaultCenter().addObserver(self, selector: Selector("keyboardWillShow:"), name: UIKeyboardWillShowNotification, object: nil)
        NSNotificationCenter.defaultCenter().addObserver(self, selector: Selector("keyboardWillHide:"), name: UIKeyboardWillHideNotification, object: nil)
    }

    deinit {
        NSNotificationCenter.defaultCenter().removeObserver(self, name: UIKeyboardWillShowNotification, object: nil)
        NSNotificationCenter.defaultCenter().removeObserver(self, name: UIKeyboardWillHideNotification, object: nil)
    }
    
    // MARK: - UITableViewController
    override func tableView(tableView: UITableView, didSelectRowAtIndexPath indexPath: NSIndexPath) {
        tableView.deselectRowAtIndexPath(indexPath, animated: true)
    }
    
    // MARK: - UIPickerViewDelegate
    func numberOfComponentsInPickerView(pickerView: UIPickerView) -> Int {
        return 1
    }
    
    func pickerView(pickerView: UIPickerView, numberOfRowsInComponent component: Int) -> Int {
        return codings.count
    }
    
    func pickerView(pickerView: UIPickerView, titleForRow row: Int, forComponent component: Int) -> String {
        return codings[row].displayName
    }
    
    // MARK: - UITextFieldDelegate
    func textFieldDidBeginEditing(textField: UITextField) {
        currentTextView = textField
    }
    
    func textFieldShouldReturn(textField: UITextField) -> Bool {
        return textField.resignFirstResponder()
    }

    // Mark: - UITextViewDelegate
    func textViewDidBeginEditing(textView: UITextView) {
        currentTextView = textView
    }
    
    // Mark: - Keyboard
    func keyboardWillShow(note: NSNotification)
    {
        let keyboardSize = (note.userInfo![UIKeyboardFrameBeginUserInfoKey] as NSValue).CGRectValue().size
        
        normalContentInset = self.tableView.contentInset
        
        let contentInsets = UIEdgeInsets(top: 0.0, left: 0.0, bottom: keyboardSize.height, right: 0.0)
        self.tableView.contentInset = contentInsets

        if let textView = currentTextView {
            let rect = self.tableView.convertRect(textView.bounds, fromView: textView)
            self.tableView.scrollRectToVisible(rect, animated: true)
        }
    }
    
    func keyboardWillHide(note: NSNotification)
    {
        UIView.animateWithDuration(0.3) {
            self.tableView.contentInset = self.normalContentInset
            self.currentTextView = nil
        }
    }
    
    override func shouldPerformSegueWithIdentifier(identifier: String?, sender: AnyObject?) -> Bool {
        if identifier == nil {
            return super.shouldPerformSegueWithIdentifier(identifier, sender: sender)
        }
        
        if !(identifier == "encode" || identifier == "decode") {
            return super.shouldPerformSegueWithIdentifier(identifier, sender: sender)
        }
        
        let currentCoding = codings[self.methodPickerView.selectedRowInComponent(0)]
            
        var iv: NSData?
        var key: NSData?
        var input: NSData?
        
        if currentCoding.ivBits != 0 {
            switch self.ivSegmentedControl.selectedSegmentIndex
            { // Text
            case 0:
                iv = ivTextField.text.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
            case 1:
                iv = Cryptor.base64_decode(ivTextField.text)
            case 2:
                iv = Cryptor.hex_decode(ivTextField.text)
            default:
                break
            }
            
            var errorMsg: String?
            if iv == nil {
                errorMsg = String(format: localizedString("IV_ERROR"), currentCoding.ivBits, currentCoding.ivBits / 8)
            }
            if iv!.length * 8 != currentCoding.ivBits {
                errorMsg = String(format: localizedString("IV_ERROR"), currentCoding.ivBits, currentCoding.ivBits / 8)
            }
            
            if let msg = errorMsg {
                UIAlertView(title: "Error", message: msg, delegate: nil, cancelButtonTitle: "OK").show()
                return false
            }
        }
        
        switch self.keySegmentedControl.selectedSegmentIndex {
        case 0:
            key = keyTextField.text.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
        case 1:
            key = Cryptor.base64_decode(keyTextField.text)
        case 2:
            key = Cryptor.hex_decode(keyTextField.text)
        default:
            break
        }

        var errorMsg: String?
        if key == nil {
            errorMsg = String(format: localizedString("KEY_ERROR"), currentCoding.keyBits, currentCoding.keyBits / 8)
        }
        if key!.length * 8 != currentCoding.keyBits {
            errorMsg = String(format: localizedString("KEY_ERROR"), currentCoding.keyBits, currentCoding.keyBits / 8)
        }
        
        if let msg = errorMsg {
            UIAlertView(title: "Error", message: msg, delegate: nil, cancelButtonTitle: "OK").show()
            return false
        }
        
        switch self.inputSegmentedControl.selectedSegmentIndex {
        case 0:
            input = inputTextView.text.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
        case 1:
            input = Cryptor.base64_decode(inputTextView.text)
        case 2:
            input = Cryptor.hex_decode(inputTextView.text)
        default:
            break
        }
        
        if input == nil {
            UIAlertView(title: "Error", message: localizedString("INPUT_ERROR"), delegate: nil, cancelButtonTitle: "OK").show()
            return false
        }
    
        if identifier! == "encode" {
            if let encoded = Cryptor.encode(currentCoding.codingNameForCryptor, withKey: key!, withData: input!, withIV: iv) {
                currentCryptData = encoded
                return true
            }
            else {
                UIAlertView(title: "Error", message: localizedString("ENCODE_ERROR"), delegate: nil, cancelButtonTitle: "OK").show()
            }
        } else if identifier! == "decode" {
            if let decoded = Cryptor.decode(currentCoding.codingNameForCryptor, withKey: key!, withData: input!, withIV: iv) {
                currentCryptData = decoded
                return true
            }
            else {
                UIAlertView(title: "Error", message: localizedString("DECODE_ERROR"), delegate: nil, cancelButtonTitle: "OK").show()
            }
        }
        return false
    }
    
    override func prepareForSegue(segue: UIStoryboardSegue, sender: AnyObject?) {
        super.prepareForSegue(segue, sender: sender)
        
        if segue.identifier == "encode" || segue.identifier == "decode" {
            if let vc = segue.destinationViewController as? EncodingDecodingResultViewController {
                vc.resultData = currentCryptData
            }
        }
    }
}
