# Definition
Structured collections of data used for analysis and model training.

## Forms
* Tabular Data: Data organized into tables with rows and columns, like a spreadsheet or database
* Image Data: Set of images represented numerically as a pixel array
* Text Data: Unstructured data composed of sentences, paragraphs, or full documents
* Time SEries Data: Sequential data points collected over time, emphasizing temporal patterns

## Quality
* High- Quality datasets produce more accurate models (garbage in/garbage out)
* Carefully curated datasets enable models to generalize more effectively to unseen data. Minimized overfitting (Making the model too specific)
* Well prepared data reduces training time and computational demands
* Reliable datasets lead to trustworthy insights and decisions.

## Attributes of a "Good" Dataset
|Attribute|Description|Example|
|---------|-----------|-------|
|`Relevance`|The data should be relevant to the problem at hand. Irrelevant data can introduce noise and reduce model performance.|Text data from social media posts is more relevant than stock market prices for a sentiment analysis task.|
|`Completeness`|The dataset should have minimal missing values. Missing data can lead to biased models and incorrect predictions.|Techniques like imputation can handle missing values, but it's best to start with a complete dataset if possible.|
|`Consistency`|Data should be consistent in format and structure. Inconsistencies can cause errors during preprocessing and model training.|Ensure that date formats are uniform across the dataset (e.g.,`YYYY-MM-DD`).|
|`Quality`|The data should be accurate and free from errors. Errors can arise from data collection, entry, or transmission issues.|Data validation and verification processes can help ensure data quality.|
|`Representativeness`|The dataset should be representative of the population it aims to model. A biased or unrepresentative dataset can lead to biased models.|A facial recognition system's dataset should include a diverse range of faces from different ethnicities, ages, and genders.|
|`Balance`|The dataset should be balanced, especially for classification tasks. Imbalanced datasets can lead to biased models that perform poorly on minority classes.|Techniques like oversampling, undersampling, or generating synthetic data can help balance the dataset.|
|`Size`|The dataset should be large enough to capture the complexity of the problem. Small datasets may not provide enough information for the model to learn effectively.|However, large datasets can also be computationally expensive and require more powerful hardware.|
