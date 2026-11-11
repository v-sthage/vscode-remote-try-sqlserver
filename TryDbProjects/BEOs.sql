CREATE TABLE [dbo].[BEOs]
(
    [Id] INT IDENTITY(1, 1) NOT NULL,
    [EventID] INT NOT NULL,
    [StartTime] TIME(0) NOT NULL,
    [Location] NVARCHAR(200) NULL,
    [Date] DATE NOT NULL,
    [EndTime] TIME(0) NULL,
    [TechAssigned] INT NULL,
    [Zone] NVARCHAR(100) NULL,
    [ImageLink] NVARCHAR(MAX) NULL,
    [Comments] NVARCHAR(MAX) NULL,
    [Available] NVARCHAR(100) NULL,
    [TurnTime] INT NULL,
    CONSTRAINT [PK_BEOs] PRIMARY KEY CLUSTERED ([Id])
);
