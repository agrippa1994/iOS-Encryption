//
//  EncodingDecodingResultViewController.swift
//  Encryption
//
//  Created by Mani on 14.12.14.
//  Copyright (c) 2014 Mani. All rights reserved.
//

import UIKit

class EncodingDecodingResultViewController: UIViewController {
    @IBOutlet var dataTextView: UITextView!
    @IBOutlet var outputSegmentControl: UISegmentedControl!
    
    var resultData: NSData?
    
    @IBAction func segmentValueChanged(sender: AnyObject) {
        showTextViewForCurrentSelection()
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        showTextViewForCurrentSelection()
    }
    
    override func viewWillAppear(animated: Bool) {
        super.viewWillAppear(animated)
        
        showTextViewForCurrentSelection()
    }
    
    func showTextViewForCurrentSelection()
    {
        if resultData == nil {
            return
        }
 
        switch outputSegmentControl.selectedSegmentIndex {
        case 0:
            dataTextView.text = Cryptor.hex_encode(resultData!)
        case 1:
            dataTextView.text = Cryptor.base64_encode(resultData!)
        case 2:
            dataTextView.text = NSString(bytes: resultData!.bytes, length: resultData!.length, encoding: NSUTF8StringEncoding)
        default:
            break
        }
    }
}
