package models

type Project struct {
	ProjectID     string `json:"id" gorm:"primaryKey;column:project_id"`
	ProjectUserID string `json:"user_id" form:"user_id"`
	Name          string `json:"name" form:"name"`
}

type UpsertProject struct {
	ProjectUserID string `json:"user_id" form:"user_id"`
	Name          string `json:"name" form:"name"`
}

func (p Project) UpsertProject() UpsertProject {
	return UpsertProject{
		Name:          p.Name,
		ProjectUserID: p.ProjectUserID,
	}
}

type GetProjectRequest struct {
	ProjectID string `json:"id"`
}

type GetProjectResponse struct {
	ProjectID     string `json:"id"`
	ProjectUserID string `json:"user_id"`
	Name          string `json:"name"`
}

type PostProjectResponse struct {
	ProjectID     string `json:"id"`
	ProjectUserID string `json:"user_id"`
	Name          string `json:"name"`
}
