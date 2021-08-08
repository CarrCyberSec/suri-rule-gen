#!/usr/bin/env python3

import logging

logging.basicConfig(filename='suri-rule-gen.log', filemode='w', format='%(asctime)s-%(levelname)s-%(message)s', datefmt='%Y-%m-%d %H:%M:%S')

logging.info('this test is logging.info')
logging.error('this test is loggin.error')
logging.log(level=1, msg='this is logging.log test')

