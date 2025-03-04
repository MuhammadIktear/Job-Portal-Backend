Problem Statement and Solution Approach for AI-Powered Job Recruitment & Skill Matching:

My core ambition is to automate resume screening, remove hiring bias, predict career growth, and enable smart job matching. I achieve this by extracting skills from both user resumes/CVs and job post descriptions. This allows me to perform job recommendations using cosine similarity, ensuring a more accurate and personalized matching process.

Here's a breakdown of the problems I address and my solution approach:

Skill Extraction from Resumes/CVs:

Problem: Resumes and CVs are typically in PDF format, and directly processing PDFs with Gemini 1.5 Flash is not supported. I need to extract the text content first before skill extraction.

Solution:

PDF to Text Conversion: I use the fitz library (PyMuPDF) to convert PDF resumes into plain text. This extracted text becomes the input for skill extraction.

Skill Extraction using Gemini 1.5 Flash: I leverage the Gemini 1.5 Flash model via the OpenRouter API. A prompt is constructed containing the extracted resume text, instructing Gemini to identify and list relevant skills. The model's response is then parsed to create a comma-separated list of skills.

Storage: Extracted skills are stored in the UserProfile model's tags field, associated with the respective user.

Skill Extraction from Job Post Descriptions:

Problem: Job descriptions are also textual and require skill extraction for effective matching.

Solution:

Skill Extraction using Gemini 1.5 Flash: Similar to resume processing, I use Gemini 1.5 Flash via OpenRouter. The job description text is passed in a prompt, asking Gemini to extract relevant skills.

Storage: Extracted skills for each job post are stored in the JobPost model's tags field.

Job Recommendation:

Problem: How to effectively match user skills with job requirements, considering the extracted skill sets.

Solution:

Count Vectorization and Cosine Similarity:

Candidate skills and job post skills are combined into a single list.

CountVectorizer converts these skill lists into numerical vectors based on word frequencies.

cosine_similarity calculates the similarity between the candidate's skill vector and each job post's skill vector. This provides a measure of how well the skills align.

Ranking: Jobs are ranked based on their cosine similarity score, with higher scores indicating a better match.

Recommendation: The top-ranked jobs are presented to the user as recommendations.

AI-Powered Career Advice:

Problem: Users might need guidance on skill development, industry trends, and career paths.

Solution:

Gemini 1.5 Flash for Personalized Advice: I use Gemini 1.5 Flash to provide career advice based on the user's skills. A prompt is crafted containing the user's skill set, and Gemini is asked to provide relevant advice, including the importance of those skills, industry demand, and latest tech trends.

Presentation: The advice generated by Gemini is displayed to the user.

Job Post Filtering:

Problem: Users need to be able to filter job posts based on various criteria to find relevant opportunities quickly.

Solution:

Filtering based on Multiple Criteria: I implement filtering functionality based on parameters like country, job type, industry, experience level, job function, and job title. These filters are applied to the JobPost queryset before serialization and display.

Chatbot Integration:

Problem: Users may have further questions or need clarification on job recommendations, skills, or career advice.

Solution:

Chatbot using Gemini 1.5 Flash: I integrate a chatbot that uses Gemini 1.5 Flash to answer user queries. User messages are sent to the OpenRouter API, and the model's response is displayed in the chat interface.

User Authentication and Management:

Problem: Secure user registration, login, and logout functionalities are essential.

Solution:

JWT Authentication: I use JSON Web Tokens (JWT) for authentication, providing secure access to protected API endpoints.

Email Verification: New users are required to verify their email addresses before their accounts are activated.

User Profile Management: Users can update their profile information, including their resume (for skill extraction).

Job Post Management (CRUD operations):

Problem: Administrators or authorized users need to be able to create, read, update, and delete job posts.

Solution:

API Endpoints for CRUD: I provide API endpoints for creating, retrieving, updating, and deleting job posts. These endpoints are protected and require appropriate authentication.

Technology Used

Details of the AI models, frameworks, and technologies used:

Backend: Django, Django REST Framework

Frontend: HTML, CSS, JavaScript

Database: SQLite3 (default Django database)

AI: Gemini 1.5 Flash (via OpenRouter API)

Frontend Git Repo: https://github.com/MuhammadIktear/Job-portal-Frontend
