from risk_engine import calculate_risk # imports calculate risk func towrite tests for it.

def test_critical(): # create first test function in pytest any func with test as start is auto recognised as test.
    assert calculate_risk(9.5) == 'Critical' # check if it is true and if returns crit then passes

def test_high(): # creates second test high severity scores.
    assert calculate_risk(7.5) == 'High'

def test_medium(): 
    assert calculate_risk(5.0) == 'Medium'

def test_low():
    assert calculate_risk(2.0) == 'Low'

def test_unknown():
    assert calculate_risk(None) == 'Unknown'
