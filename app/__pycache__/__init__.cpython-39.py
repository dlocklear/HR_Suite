a
    s�.f�  �                   @   sB   d dl Z d dlmZmZ d dlmZ d dlmZ e�  dd� ZdS )�    N)�create_client�Client)�Flask)�load_dotenvc                  C   sB   t t�} tj�d�}tj�d�}t||�}ddlm} || � | S )NZSUPABASE_URLZSUPABASE_ANON_KEYr   )�init_routes)r   �__name__�os�environ�getr   Z
app.routesr   )�appZurl�key�supabaser   � r   �"D:\Github\HR_Suite\app\__init__.py�
create_app   s    
r   )	r   r   r   r   Zflaskr   Zdotenvr   r   r   r   r   r   �<module>   s
   