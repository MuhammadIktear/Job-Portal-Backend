Problem statement and Solution Approach for AI-Powered Job Recruitment & Skill Matching
Our core ambition is to automate resume screening, remove hiring bias, predict career growth, and enable smart job matching. We achieve this by extracting skills from both user resumes/CVs and job post descriptions. This allows us to perform job recommendations using cosine similarity, ensuring a more accurate and personalized matching process.

Here's a breakdown of the problems we address and our solution approach:
1. Skill Extraction from Resumes/CVs:
Problem: Resumes and CVs are typically in PDF format, and directly processing PDFs with Gemini 1.5 Flash is not supported. We need to extract the text content first before skill extraction.
Solution:
PDF to Text Conversion: We use the fitz library (PyMuPDF) to convert PDF resumes into plain text. This extracted text becomes the input for skill extraction.
Skill Extraction using Gemini 1.5 Flash: We leverage the Gemini 1.5 Flash model via the OpenRouter API. A prompt is constructed containing the extracted resume text, instructing Gemini to identify and list relevant skills. The model's response is then parsed to create a comma-separated list of skills.
Storage: Extracted skills are stored in the UserProfile model's tags field, associated with the respective user.
2. Skill Extraction from Job Post Descriptions:
Problem: Job descriptions are also textual and require skill extraction for effective matching.
Solution:
Skill Extraction using Gemini 1.5 Flash: Similar to resume processing, we use Gemini 1.5 Flash via OpenRouter. The job description text is passed in a prompt, asking Gemini to extract relevant skills.
Storage: Extracted skills for each job post are stored in the JobPost model's tags field.
3. Job Recommendation:
Problem: How to effectively match user skills with job requirements, considering the extracted skill sets.
Solution:
Count Vectorization and Cosine Similarity:
Candidate skills and job post skills are combined into a single list.
CountVectorizer converts these skill lists into numerical vectors based on word frequencies.
cosine_similarity calculates the similarity between the candidate's skill vector and each job post's skill vector. This provides a measure of how well the skills align.
Ranking: Jobs are ranked based on their cosine similarity score, with higher scores indicating a better match.
Recommendation: The top-ranked jobs are presented to the user as recommendations.
4. AI-Powered Career Advice:
Problem: Users might need guidance on skill development, industry trends, and career paths.
Solution:
Gemini 1.5 Flash for Personalized Advice: We use Gemini 1.5 Flash to provide career advice based on the user's skills. A prompt is crafted containing the user's skill set, and Gemini is asked to provide relevant advice, including the importance of those skills, industry demand, and latest tech trends.
Presentation: The advice generated by Gemini is displayed to the user.
5. Job Post Filtering:
Problem: Users need to be able to filter job posts based on various criteria to find relevant opportunities quickly.
Solution:
Filtering based on Multiple Criteria: We implement filtering functionality based on parameters like country, job type, industry, experience level, job function, and job title. These filters are applied to the JobPost queryset before serialization and display.
6. Chatbot Integration:
Problem: Users may have further questions or need clarification on job recommendations, skills, or career advice.
Solution:
Chatbot using Gemini 1.5 Flash: We integrate a chatbot that uses Gemini 1.5 Flash to answer user queries. User messages are sent to the OpenRouter API, and the model's response is displayed in the chat interface.
7. User Authentication and Management:
Problem: Secure user registration, login, and logout functionalities are essential.
Solution:
JWT Authentication: We use JSON Web Tokens (JWT) for authentication, providing secure access to protected API endpoints.
Email Verification: New users are required to verify their email addresses before their accounts are activated.
User Profile Management: Users can update their profile information, including their resume (for skill extraction).
8. Job Post Management (CRUD operations):
Problem: Administrators or authorized users need to be able to create, read, update, and delete job posts.
Solution:
API Endpoints for CRUD: We provide API endpoints for creating, retrieving, updating, and deleting job posts. These endpoints are protected and require appropriate authentication.






3. Technology Used – Details of the AI models, frameworks, and technologies used.
Backend: Django, Django REST Framework
Frontend: HTML, CSS, JavaScript
Database: SQLite3 (default Django database)
AI: Gemini 1.5 Flash (via OpenRouter API)


Fronted Git repo: https://github.com/MuhammadIktear/Job-portal-Frontend
