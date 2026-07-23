from airiskguard_gateway.routing.classifier import classify, TaskType, Complexity


def test_simple_qa_classification():
    s = classify("What is the capital of France?")
    assert s.task_type == TaskType.SIMPLE_QA
    assert s.complexity == Complexity.LOW
    assert s.language == "en"


def test_code_generation():
    s = classify("Write a Python function to sort a list of dictionaries by key.")
    assert s.task_type == TaskType.CODE_GENERATION
    assert s.has_code is False  # no code block, but keywords match


def test_code_block_detection():
    s = classify("Fix this:\n```python\ndef foo():\n    pass\n```")
    assert s.task_type == TaskType.CODE_GENERATION
    assert s.has_code is True


def test_summarization():
    s = classify("Please summarize the following article in 3 bullet points.")
    assert s.task_type == TaskType.SUMMARIZATION


def test_translation():
    s = classify("Translate the following text to Chinese.")
    assert s.task_type == TaskType.TRANSLATION


def test_complex_reasoning():
    long_prompt = "Analyze the trade-offs between microservices and monolithic architecture " * 20
    s = classify(long_prompt)
    assert s.complexity == Complexity.HIGH


def test_chinese_language_detection():
    s = classify("请帮我写一个Python函数来排序列表")
    assert s.language == "zh"
    assert s.task_type == TaskType.CODE_GENERATION


def test_data_analysis():
    s = classify("Calculate the average revenue per user from this dataset.")
    assert s.task_type == TaskType.DATA_ANALYSIS


def test_financial_data_low_complexity():
    s = classify("What is IBAN?")
    assert s.complexity == Complexity.LOW
